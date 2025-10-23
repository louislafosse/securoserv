#!/usr/bin/env sh
set -euo pipefail

echo "Generating certificate for pinning (single cert for both server and client)..."

# Generate PKCS#8 private key
openssl genpkey -algorithm RSA -out key.pem -pkeyopt rsa_keygen_bits:2048

# Generate self-signed certificate with SAN and both serverAuth + clientAuth
openssl req -x509 -new -key key.pem -out cert.pem -days 365 \
  -subj "/CN=localhost" \
  -addext "subjectAltName = DNS:localhost,IP:127.0.0.1" \
  -addext "extendedKeyUsage = serverAuth,clientAuth"

echo ""
echo "✅ Certificate and key generated:"
echo "   - cert.pem (server + client certificate)"
echo "   - key.pem (private key)"
echo ""
echo "To test the server:"
echo "  USE_TLS=true cargo run"
echo ""
echo "To test with curl (using the same cert as client):"
echo "  curl --cacert cert.pem --cert cert.pem --key key.pem https://127.0.0.1:8443/"
echo ""
echo "To test rejection (without client cert):"
echo "  curl -k https://127.0.0.1:8443/"
echo "  (should fail with TLS handshake error)"

# rm *.csr
# rm *.srl
# rm *.cnf
# rm ca.cert.pem
# rm ca.key.pem
# rm client.cert.pem
# # rm client-key.pem
# # rm client.pem
# rm server.cert.pem