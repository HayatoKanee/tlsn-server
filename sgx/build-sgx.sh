#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "==> Building SGX Docker image..."
docker build -f "$SCRIPT_DIR/Dockerfile.sgx" -t tlsn-server-sgx "$PROJECT_DIR"

echo ""
echo "==> Build complete. MRENCLAVE (for client verification):"
docker run --rm tlsn-server-sgx gramine-sgx-sigstruct-view /app/tlsn-server.sig
