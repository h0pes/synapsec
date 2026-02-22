#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="$(dirname "$0")/../nginx/certs"
mkdir -p "$CERT_DIR"

if ! command -v mkcert &> /dev/null; then
    echo "Error: mkcert is not installed. Install it first:"
    echo "  https://github.com/FiloSottile/mkcert#installation"
    exit 1
fi

# Install local CA if not already done
mkcert -install

# Generate certificates for local development
mkcert -cert-file "$CERT_DIR/localhost+2.pem" \
       -key-file "$CERT_DIR/localhost+2-key.pem" \
       localhost 127.0.0.1 ::1

echo "Certificates generated in $CERT_DIR"
