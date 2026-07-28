#!/usr/bin/env bash
#
# build.sh - Build osv-mcp from source
#
# Usage:
#   ./build.sh              Build release binary
#   ./build.sh --debug      Build debug binary (faster compile, slower runtime)
#   ./build.sh --test       Build and run tests
#   ./build.sh --help       Show this help
#
set -euo pipefail

BINARY="osv-mcp"
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

usage() {
    sed -n '3,11p' "$0"
    exit 0
}

# Parse arguments
PROFILE="release"
RUN_TESTS=false

for arg in "$@"; do
    case "$arg" in
        --debug)   PROFILE="debug" ;;
        --test)    RUN_TESTS=true ;;
        --help|-h) usage ;;
    esac
done

echo "==> Building ${BINARY} (${PROFILE} mode)..."

if [ "$PROFILE" = "release" ]; then
    cargo build --release --manifest-path "${PROJECT_DIR}/Cargo.toml"
    BINARY_PATH="${PROJECT_DIR}/target/release/${BINARY}"
else
    cargo build --manifest-path "${PROJECT_DIR}/Cargo.toml"
    BINARY_PATH="${PROJECT_DIR}/target/debug/${BINARY}"
fi

if [ ! -f "$BINARY_PATH" ]; then
    echo "!!> Build failed: binary not found at ${BINARY_PATH}"
    exit 1
fi

echo "==> Binary built: ${BINARY_PATH}"
echo "==> Binary size: $(du -h "$BINARY_PATH" | cut -f1)"

if [ "$RUN_TESTS" = true ]; then
    echo ""
    echo "==> Running tests..."
    cargo test --manifest-path "${PROJECT_DIR}/Cargo.toml"
fi

echo ""
echo "Done. To configure in Open Grok, add to ~/.opengrok/config.toml:"
echo ""
echo "  [mcp_servers.osv-mcp]"
echo "  command = \"${BINARY_PATH}\""
echo "  enabled = true"
echo ""