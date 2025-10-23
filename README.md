<div align="center">

# SecuroServ

</div>

<div align="center">
  <img src="./docs/logo.png" alt="SecuroServ Logo" width="400"/>
</div>

**An attempt to make an Hybrid Post quantum End-to-End Encryption: Ephemeral X25519 + Kyber-1024 key exchange, XSalsa20-Poly1305 AEAD encryption, Ed25519 signatures, TLS 1.3 pinning, replay protection.**

## Quick start
Build and run the server and client locally (TLS pinning enabled in client):

```bash
# Build
cargo build --release

# Start server (with TLS):
cd securoserv
bash ./scripts/gen-pinned-cert.sh
USE_TLS=true ./target/release/securoserv

# Run client tests:
cd securoclient
./target/release/securoclient
```

## [Security Architecture](./docs/SECURITY_ARCHITECTURE.md)
## [Authentication Architecture](./docs/AUTHENTICATION_ARCHITECTURE.md)