#!/usr/bin/env bash
#
# Build keychat-cli for the current platform and update the Homebrew formula.
#
# Usage:
#   ./scripts/release-cli.sh [version]
#
# Examples:
#   ./scripts/release-cli.sh 0.1.0
#   ./scripts/release-cli.sh          # reads version from Cargo.toml
#
# Prerequisites:
#   - Rust toolchain with targets: aarch64-apple-darwin, x86_64-apple-darwin
#   - gh CLI (for creating GitHub releases)
#   - Homebrew tap repo at ../homebrew-tap (relative to this repo root)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TAP_DIR="${REPO_ROOT}/../homebrew-tap"
FORMULA="${TAP_DIR}/Formula/keychat.rb"

# Read version from argument or Cargo.toml
VERSION="${1:-$(grep '^version' "${REPO_ROOT}/keychat-cli/Cargo.toml" | head -1 | sed 's/.*"\(.*\)"/\1/')}"
TAG="v${VERSION}"

echo "==> Building keychat-cli ${VERSION}"

# macOS targets
TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)
ARCHIVES=()

for target in "${TARGETS[@]}"; do
    echo "==> Building for ${target}..."
    cargo build --release -p keychat-cli --target "${target}" --manifest-path "${REPO_ROOT}/Cargo.toml"

    archive="keychat-${target}.tar.gz"
    tar -czf "${REPO_ROOT}/${archive}" -C "${REPO_ROOT}/target/${target}/release" keychat
    ARCHIVES+=("${archive}")
    echo "    Created ${archive}"
done

# Compute SHA256 hashes
echo ""
echo "==> SHA256 checksums:"
declare -A SHAS
for archive in "${ARCHIVES[@]}"; do
    sha=$(shasum -a 256 "${REPO_ROOT}/${archive}" | awk '{print $1}')
    SHAS["${archive}"]="${sha}"
    echo "    ${archive}: ${sha}"
done

# Create GitHub release (draft)
echo ""
echo "==> Creating GitHub release ${TAG}..."
cd "${REPO_ROOT}"

# Create tag if it doesn't exist
if ! git rev-parse "${TAG}" >/dev/null 2>&1; then
    git tag "${TAG}"
    git push origin "${TAG}"
fi

gh release create "${TAG}" \
    --title "keychat-cli ${VERSION}" \
    --notes "keychat-cli release ${VERSION}" \
    --draft \
    "${ARCHIVES[@]/#/${REPO_ROOT}/}"

echo "    Draft release created. Review and publish at:"
echo "    https://github.com/keychat-io/keychat-protocol/releases/tag/${TAG}"

# Update Homebrew formula
echo ""
echo "==> Updating Homebrew formula..."

if [[ ! -f "${FORMULA}" ]]; then
    echo "ERROR: Formula not found at ${FORMULA}"
    exit 1
fi

# Update version
sed -i '' "s/version \".*\"/version \"${VERSION}\"/" "${FORMULA}"

# Update URLs and SHA256 for each target
for target in "${TARGETS[@]}"; do
    archive="keychat-${target}.tar.gz"
    sha="${SHAS[${archive}]}"
    old_url_pattern="keychat-protocol/releases/download/v[^/]*/keychat-${target}.tar.gz"
    new_url="keychat-protocol/releases/download/${TAG}/keychat-${target}.tar.gz"
    sed -i '' "s|${old_url_pattern}|${new_url}|" "${FORMULA}"

    # Replace the sha256 on the line following the URL for this target
    python3 -c "
import re, sys
with open('${FORMULA}') as f:
    lines = f.readlines()
for i, line in enumerate(lines):
    if '${target}' in line and 'url' in line:
        # Next line should be sha256
        for j in range(i+1, min(i+3, len(lines))):
            if 'sha256' in lines[j]:
                lines[j] = re.sub(r'sha256 \"[^\"]*\"', 'sha256 \"${sha}\"', lines[j])
                break
        break
with open('${FORMULA}', 'w') as f:
    f.writelines(lines)
"
done

echo "    Formula updated: ${FORMULA}"

# Commit and push tap
echo ""
echo "==> Committing Homebrew tap..."
cd "${TAP_DIR}"
git add -A
git commit -m "keychat ${VERSION}"
git push origin main

echo ""
echo "==> Done! Next steps:"
echo "    1. Go to https://github.com/keychat-io/keychat-protocol/releases/tag/${TAG}"
echo "    2. Review the draft release and click 'Publish'"
echo "    3. Users can install with: brew tap keychat-io/tap && brew install keychat"
