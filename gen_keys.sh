#!/bin/bash
set -e

echo "Generating cryptographic keys..."
echo ""

# Create keys directory if it doesn't exist
mkdir -p keys

# Generate RSA keypair (private + public)
echo "1/2 Generating RSA-3072 keypair..."
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out keys/rsa_private.pem
openssl rsa -in keys/rsa_private.pem -pubout -out keys/rsa_public.pem
echo "✓ RSA private key: keys/rsa_private.pem"
echo "✓ RSA public key: keys/rsa_public.pem"
echo ""

# Generate Dilithium keypair using proper Rust cryptographic library
echo "2/2 Generating Dilithium3 keypair..."
cargo run --bin gen-dilithium
echo ""

# Set restrictive permissions on private keys
chmod 600 keys/rsa_private.pem keys/dilithium_sk.bin
chmod 644 keys/rsa_public.pem keys/dilithium_pk.bin

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✓ All keys generated successfully!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "⚠️  SECURITY WARNING:"
echo "  - Keep private keys (rsa_private.pem, dilithium_sk.bin) SECRET"
echo "  - Never commit keys to version control"
echo "  - Store in secure key management system (HSM/Vault) for production"
echo "  - Private key permissions set to 600 (owner read/write only)"
echo ""
