#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# iOS projects that consume this XCFramework
IOS_TARGETS=(
    "$PROJECT_DIR/../keychat-agent-chat-iOS"
    "$PROJECT_DIR/../keychat-ios-native"
)
TMP_DIR="$SCRIPT_DIR/.build-tmp"

cd "$PROJECT_DIR"

# Clean temp
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR/swift" "$TMP_DIR/headers"

# Build for iOS device (aarch64)
echo "==> Building for iOS (aarch64-apple-ios)..."
cargo build --release --target aarch64-apple-ios -p keychat-uniffi

# Build for iOS Simulator (aarch64 - Apple Silicon)
echo "==> Building for iOS Simulator (aarch64-apple-ios-sim)..."
cargo build --release --target aarch64-apple-ios-sim -p keychat-uniffi

# Generate Swift bindings using host-built library
echo "==> Building host library for bindgen..."
cargo build --release -p keychat-uniffi

echo "==> Generating Swift bindings..."
cargo run -p keychat-uniffi --bin uniffi-bindgen generate \
    --library target/release/libkeychat_uniffi.dylib \
    --language swift \
    --out-dir "$TMP_DIR/swift"

# Create XCFramework
echo "==> Creating XCFramework..."

cp "$TMP_DIR/swift/"*.h "$TMP_DIR/headers/" 2>/dev/null || true
cat > "$TMP_DIR/headers/module.modulemap" << 'MODULEMAP'
module keychat_uniffiFFI {
    header "keychat_uniffiFFI.h"
    export *
}
MODULEMAP

rm -rf "$TMP_DIR/KeychatFFI.xcframework"
xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libkeychat_uniffi.a \
    -headers "$TMP_DIR/headers/" \
    -library target/aarch64-apple-ios-sim/release/libkeychat_uniffi.a \
    -headers "$TMP_DIR/headers/" \
    -output "$TMP_DIR/KeychatFFI.xcframework"

# Deploy to each iOS project that exists
DEPLOYED=0
for TARGET_DIR in "${IOS_TARGETS[@]}"; do
    RESOLVED_DIR="$(cd "$TARGET_DIR" 2>/dev/null && pwd)" || continue
    PROJECT_NAME="$(basename "$RESOLVED_DIR")"
    echo "==> Deploying to $PROJECT_NAME ..."
    rm -rf "$RESOLVED_DIR/KeychatFFI.xcframework"
    cp -R "$TMP_DIR/KeychatFFI.xcframework" "$RESOLVED_DIR/KeychatFFI.xcframework"
    if [[ -d "$RESOLVED_DIR/agentChat/Services" ]]; then
        cp "$TMP_DIR/swift/KeychatFFI.swift" "$RESOLVED_DIR/agentChat/Services/KeychatFFI.swift"
        sed -i '' 's/                uniffiFutureContinuationCallback,/                { handle, pollResult in uniffiFutureContinuationCallback(handle: handle, pollResult: pollResult) },/' \
            "$RESOLVED_DIR/agentChat/Services/KeychatFFI.swift"
    fi
    DEPLOYED=$((DEPLOYED + 1))
done

# Clean temp
rm -rf "$TMP_DIR"

echo ""
echo "==> Done!"
echo "    XCFramework deployed to $DEPLOYED project(s)"
for TARGET_DIR in "${IOS_TARGETS[@]}"; do
    if [[ -d "$TARGET_DIR/KeychatFFI.xcframework" ]]; then
        echo "    ✓ $(basename "$TARGET_DIR")"
    fi
done
