#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$SCRIPT_DIR/generated"

cd "$PROJECT_DIR"

# Clean output
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/swift"

# Build for iOS device (aarch64)
echo "==> Building for iOS (aarch64-apple-ios)..."
cargo build --release --target aarch64-apple-ios -p keychat-uniffi

# Build for iOS Simulator (aarch64 - Apple Silicon simulators)
echo "==> Building for iOS Simulator (aarch64-apple-ios-sim)..."
cargo build --release --target aarch64-apple-ios-sim -p keychat-uniffi

# Generate Swift bindings using host-built library
echo "==> Building host library for bindgen..."
cargo build --release -p keychat-uniffi

echo "==> Generating Swift bindings..."
cargo run -p keychat-uniffi --bin uniffi-bindgen generate \
    --library target/release/libkeychat_uniffi.dylib \
    --language swift \
    --out-dir "$OUT_DIR/swift"

# Create XCFramework
echo "==> Creating XCFramework..."

# The generated headers need a module.modulemap
mkdir -p "$OUT_DIR/headers"
cp "$OUT_DIR/swift/"*.h "$OUT_DIR/headers/" 2>/dev/null || true
cat > "$OUT_DIR/headers/module.modulemap" << 'MODULEMAP'
framework module keychat_uniffiFFI {
    header "keychat_uniffiFFI.h"
    export *
}
MODULEMAP

# Remove existing xcframework if present
rm -rf "$OUT_DIR/KeychatFFI.xcframework"

xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libkeychat_uniffi.a \
    -headers "$OUT_DIR/headers/" \
    -library target/aarch64-apple-ios-sim/release/libkeychat_uniffi.a \
    -headers "$OUT_DIR/headers/" \
    -output "$OUT_DIR/KeychatFFI.xcframework"

echo ""
echo "==> Done!"
echo "    XCFramework: $OUT_DIR/KeychatFFI.xcframework"
echo "    Swift sources: $OUT_DIR/swift/"
echo ""
echo "To use in your iOS project:"
echo "  1. Add KeychatFFI.xcframework to your Xcode project"
echo "  2. Copy the generated .swift file(s) into your project"
