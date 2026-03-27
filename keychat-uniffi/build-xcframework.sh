#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
IOS_DIR="$(cd "$PROJECT_DIR/../keychat-iOS" && pwd)"
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

# Deploy to iOS project
echo "==> Deploying to $IOS_DIR ..."
rm -rf "$IOS_DIR/KeychatFFI.xcframework"
cp -R "$TMP_DIR/KeychatFFI.xcframework" "$IOS_DIR/KeychatFFI.xcframework"
cp "$TMP_DIR/swift/KeychatFFI.swift" "$IOS_DIR/agentChat/Services/KeychatFFI.swift"

# Patch: UniFFI generates a function reference that Xcode 26 / Swift 6 rejects as
# "a C function pointer can only be formed from a reference to a 'func' or a literal closure".
# Wrap it in a literal closure to satisfy the compiler.
echo "==> Patching Swift bindings for Xcode 26 compatibility..."
sed -i '' 's/                uniffiFutureContinuationCallback,/                { handle, pollResult in uniffiFutureContinuationCallback(handle: handle, pollResult: pollResult) },/' \
    "$IOS_DIR/agentChat/Services/KeychatFFI.swift"

# Clean temp
rm -rf "$TMP_DIR"

echo ""
echo "==> Done!"
echo "    XCFramework → $IOS_DIR/KeychatFFI.xcframework"
echo "    Swift bindings → $IOS_DIR/agentChat/Services/KeychatFFI.swift"
