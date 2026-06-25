#!/bin/bash
# ============================================================
# Build sing-box with CNS outbound for Android
# Requires: Go 1.24+
# ============================================================

set -e

# Configuration
ANDROID_API=21
BUILD_TAGS="with_gvisor,with_quic,with_utls,with_clash_api,with_ccm,with_ocm,badlinkname,tfogo_checklinkname0"
LDFLAGS="-s -w -buildid= -X internal/godebug.defaultGODEBUG=multipathtcp=0 -checklinkname=0"
OUTPUT_DIR="output"
VERSION=$(go run ./cmd/internal/read_tag 2>/dev/null || echo "1.13.13-cns")
mkdir -p "$OUTPUT_DIR"

echo "=== Building sing-box with CNS outbound v${VERSION} for Android ==="

# arm64 (64-bit, most modern devices)
echo "[1/4] Building for android/arm64..."
GOOS=android GOARCH=arm64 CGO_ENABLED=0 \
  go build -v -trimpath -tags "$BUILD_TAGS" \
    -ldflags "-X github.com/sagernet/sing-box/constant.Version=${VERSION} $LDFLAGS" \
    -o "$OUTPUT_DIR/sing-box-arm64" ./cmd/sing-box
echo "  -> $OUTPUT_DIR/sing-box-arm64"

# arm (32-bit)
echo "[2/4] Building for android/arm (v7)..."
GOOS=android GOARCH=arm GOARM=7 CGO_ENABLED=0 \
  go build -v -trimpath -tags "$BUILD_TAGS" \
    -ldflags "-X github.com/sagernet/sing-box/constant.Version=${VERSION} $LDFLAGS" \
    -o "$OUTPUT_DIR/sing-box-arm" ./cmd/sing-box
echo "  -> $OUTPUT_DIR/sing-box-arm"

# amd64
echo "[3/4] Building for android/amd64..."
GOOS=android GOARCH=amd64 CGO_ENABLED=0 \
  go build -v -trimpath -tags "$BUILD_TAGS" \
    -ldflags "-X github.com/sagernet/sing-box/constant.Version=${VERSION} $LDFLAGS" \
    -o "$OUTPUT_DIR/sing-box-amd64" ./cmd/sing-box
echo "  -> $OUTPUT_DIR/sing-box-amd64"

# 386
echo "[4/4] Building for android/386..."
GOOS=android GOARCH=386 CGO_ENABLED=0 \
  go build -v -trimpath -tags "$BUILD_TAGS" \
    -ldflags "-X github.com/sagernet/sing-box/constant.Version=${VERSION} $LDFLAGS" \
    -o "$OUTPUT_DIR/sing-box-386" ./cmd/sing-box
echo "  -> $OUTPUT_DIR/sing-box-386"

echo ""
echo "=========================================="
echo "BUILD SUCCESS! Output files in: $OUTPUT_DIR"
echo "=========================================="
echo ""
echo "To deploy to Android device:"
echo "  adb push output/sing-box-arm64 /data/local/tmp/sing-box"
echo "  adb shell chmod 755 /data/local/tmp/sing-box"
echo "  adb shell /data/local/tmp/sing-box run -c /data/local/tmp/config.json"
