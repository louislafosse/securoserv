//! # Securo — Cryptographic Imp for Secure Authentication
//!
//!
//! **Read [Securoserv](https://github.com/louislafosse/securo/tree/main/securoserv) and [Securoclient](https://github.com/louislafosse/securo/tree/main/securoclient) for exact implementation of Securo**
//!
//! This crate provides the **cryptographic Impl** for an authentication and communication system.
//! It implements a hybrid classical-post-quantum key exchange protocol, session encryption, and certificate pinning
//! to establish secure, authenticated connections between client and server.
//!
//! ## Core Responsibilities
//!
//! 1. **Hybrid Key Exchange** — Combines X25519 (ECDH), Kyber-1024 (post-quantum KEM), and HKDF for key derivation
//! 2. **End-to-End Encryption** — XSalsa20-Poly1305 (AEAD) for encrypting request/response payloads
//! 3. **Authentication** — Ed25519 signatures and HMAC-SHA256 for verifying message integrity and server identity
//! 4. **Certificate Pinning** — Hardcoded certificate validation to prevent CA compromises
//! 5. **TLS Configuration** — Rustls setup with optional mutual-TLS (mTLS) support
//!
//! ## Library Architecture
//!
//! The securo library exposes cryptographic helpers organized into:
//!
//! - [`server`] — Server-side initialization: TLS config, key exchange handlers, payload encryption/decryption
//! - [`client`] — Client-side initialization: certificate pinning, key exchange participation, request signing
//! - [`tls`] — TLS mode configuration (NormalPinning vs. MutualTlsPinning)
//! - The `crypto` submodules — Low-level cryptographic primitives (signing, encryption, Kyber operations)
//!
//! ## Key Exchange Protocol Overview
//!
//! The library implements a multi-stage key exchange:
//!
//! 1. **Stage 1** — Server sends ephemeral X25519 keys and Ed25519 verifying key
//! 2. **Stage 2** — Client responds with encrypted static keys (X25519 + Kyber-1024 public key)
//! 3. **Key Derivation** — HKDF combines classical DH (X25519) and post-quantum KEM (Kyber-1024) secrets
//! 4. **Session Encryption** — All subsequent messages encrypted with XSalsa20-Poly1305 using the derived key
//!
//! This design provides:
//! - **Post-quantum resilience** — Kyber-1024 protects against future quantum attacks
//! - **Forward secrecy** — Per-session ephemeral keys prevent long-term key compromise
//! - **Cryptographic authentication** — Ed25519 signatures prevent MITM attacks
//!
//! ## TLS Configuration & Certificate Pinning
//!
//! The library manages TLS layer security through:
//!
//! - **Certificate Pinning** — Hardcoded certificate validation to prevent CA compromises
//! - **Mutual TLS (mTLS)** — Optional bidirectional client/server certificate authentication
//!
//! Two TLS modes are supported:
//!
//! - `TlsMode::NormalPinning` — Server certificate pinning only, no client certificates required
//! - `TlsMode::MutualTlsPinning` — Bidirectional certificate pinning with client authentication
//!
//! ## Quick Start
//!
//! ### Server Initialization
//!
//! ```ignore
//! use securo::server::pin::init_rustls_config;
//! use securo::tls::TlsMode;
//!
//! let tls_config = init_rustls_config(
//!     &cert_bytes,
//!     &key_bytes,
//!     TlsMode::NormalPinning
//! )?;
//! ```
//!
//! ### Client Initialization
//!
//! ```ignore
//! use securo::client::pin::create::pinned_rustls_config;
//! use securo::tls::TlsMode;
//!
//! let client_config = pinned_rustls_config(
//!     &server_cert_bytes,
//!     None,  // No client cert for NormalPinning
//!     TlsMode::NormalPinning
//! );
//! ```
//!
//! ## Implementing the Cryptographic Part
//!
//! The library exposes core building blocks in [`server::crypto`] and [`client::crypto`].
//! Below are concrete examples showing how to use the library APIs to perform the two-stage exchange
//! and encrypt/decrypt messages.
//!
//! ### Server-side (quick example)
//!
//! Use [`server::crypto::SecuroServ`] to handle key exchange and token generation:
//!
//! ```ignore
//! use securo::server::crypto::SecuroServ;
//! use uuid::Uuid;
//!
//! // Initialize server crypto state
//! let server = SecuroServ::new();
//!
//! // Stage 1: generate values to send to the client
//! let stage1 = server.perform_exchange_stage1()?; // ExchangeStage1Response
//!
//! // After receiving client's Stage 2 request (from HTTP handler)
//! let req: securo::server::crypto::ExchangeStage2Request = /* deserialize from request */;
//! let resp = server.perform_exchange_stage2(req)?; // ExchangeStage2Response
//!
//! // At this point server may generate tokens and create session state
//! let session_id = Uuid::new_v4();
//! let tokens = server.generate_token_pair(&session_id)?;
//! ```
//!
//! Important server functions:
//!
//! - [`server::crypto::SecuroServ::perform_exchange_stage1`] → `ExchangeStage1Response`
//! - [`server::crypto::SecuroServ::perform_exchange_stage2`] → `ExchangeStage2Response`
//! - [`server::crypto::SecuroServ::perform_exchange`] (single-step variant) → `ExchangeResponse`
//! - [`server::crypto::SecuroServ::generate_token_pair`] → `TokenPair`
//!
//! ### Client-side (quick example)
//!
//! Use [`client::crypto::SecuroClient`] to perform the exchange and encrypt/decrypt messages:
//!
//! ```ignore
//! use securo::client::crypto::SecuroClient;
//!
//! let mut client = SecuroClient::new();
//!
//! // 1) call server /api/exchange/stage1 and parse ExchangeStage1Response
//! let server_stage1 = /* http call */;
//!
//! // 2) prepare client payload for stage 2
//! let encrypted_payload_b64 = client.encrypt_client_keys_stage2(
//!     &server_stage1.server_x25519_public,
//!     &server_stage1.server_ephemeral_public
//! )?;
//!
//! // 3) send Stage2 request and receive ExchangeStage2Response
//! let stage2_resp = /* http call */;
//! client.process_stage2_response(&stage2_resp)?; // verifies server signature, decapsulates Kyber, sets shared secret
//!
//! // 4) After auth, encrypt requests
//! let payload = b"{ \"action\": \"ping\" }";
//! let enc_req = client.encrypt_request(payload, client.kyber_shared_secret.as_ref().unwrap())?;
//!
//! // 5) send to `/api/encrypted` and when receiving response, decrypt
//! let server_resp: securo::client::crypto::EncryptedResponse = /* http response */;
//! let plaintext = client.decrypt_response(&server_resp, client.kyber_shared_secret.as_ref().unwrap())?;
//! ```
//!
//! Important client methods:
//!
//! - [`client::crypto::SecuroClient::new`] / [`client::crypto::SecuroClient::new_with_logger`] — create client state
//! - `get_public_key_base64()`, `get_ephemeral_public_base64()`, `get_kyber_public_base64()`, `get_verifying_key_base64()` — getters used during exchange
//! - [`client::crypto::SecuroClient::encrypt_client_keys_stage2`] — prepare Stage 2 ciphertext
//! - [`client::crypto::SecuroClient::process_stage2_response`] — full Stage 2 processing (verify + decapsulate)
//! - [`client::crypto::SecuroClient::decapsulate_kyber`] — decapsulates Kyber ciphertext when needed
//! - [`client::crypto::SecuroClient::encrypt_request`] — encrypt request payload
//! - [`client::crypto::SecuroClient::decrypt_response`] — decrypt and verify server response
//!
//! ### Integration Notes
//!
//! - **Server state**: The server stores temporary ephemeral values (see `PendingExchange` in [`server::crypto`])
//!   which are bound by `stage_token` to prevent stage mismatches—keep server-side state consistent between Stage1 and Stage2 handlers.
//! - **TLS layer**: Use [`server::pin::init_rustls_config`] and [`client::pin::create::pinned_rustls_config`] for TLS setup
//!   and certificate pinning; these are orthogonal to application-layer crypto and should be applied at transport setup time.
//! - **Session lookup**: The `EncryptedRequest` structure contains `session_id` (UUID) used for O(1) lookups on the server—set it after authentication.
//! - **Nonce validation**: Nonces must be 24 bytes for XSalsa20-Poly1305 and should be random and unique per message.
//!   Verify timestamps per security guidelines; requests must fall within a 60-second TTL window.
//!
//! ## TLS Configuration & Certificate Pinning
//!
//! The library manages TLS layer security through:
//!
//! - **Certificate Pinning** — Hardcoded certificate validation to prevent CA compromises
//! - **Mutual TLS (mTLS)** — Optional bidirectional client/server certificate authentication
//!
//! Two TLS modes are supported via [`tls::TlsMode`]:
//!
//! - `TlsMode::NormalPinning` — Server certificate pinning only, no client certificates required
//! - `TlsMode::MutualTlsPinning` — Bidirectional certificate pinning with client authentication
//!
//! ### Server TLS Initialization
//!
//! Use [`server::pin::init_rustls_config`]:
//!
//! ```ignore
//! use securo::server::pin::init_rustls_config;
//! use securo::tls::TlsMode;
//!
//! let tls_config = init_rustls_config(
//!     &cert_bytes,
//!     &key_bytes,
//!     TlsMode::NormalPinning
//! )?;
//! ```
//!
//! **Function signature**:
//! ```ignore
//! pub fn init_rustls_config(
//!     cert: &[u8],
//!     key: &[u8],
//!     mode: TlsMode
//! ) -> rustls::ServerConfig
//! ```
//!
//! ### Client TLS Initialization
//!
//! Use [`client::pin::create::pinned_rustls_config`]:
//!
//! ```ignore
//! use securo::client::pin::create::pinned_rustls_config;
//! use securo::tls::TlsMode;
//!
//! let client_config = pinned_rustls_config(
//!     &server_cert_bytes,
//!     None,  // No client cert for NormalPinning
//!     TlsMode::NormalPinning
//! );
//! ```
//!
//! **Function signature**:
//! ```ignore
//! pub fn pinned_rustls_config(
//!     cert: &[u8],
//!     key: Option<&[u8]>,
//!     mode: TlsMode
//! ) -> Arc<ClientConfig>
//! ```
//!
//! ## Server Cryptography — Data Structures & Functions
//!
//! See module [`server::crypto`] for implementation.
//!
//! ### Server Data Structures
//!
//! **`ExchangeStage1Response`** — Sent by server in Stage 1 of key exchange:
//! ```ignore
//! pub struct ExchangeStage1Response {
//!     pub server_x25519_public: String,           // Base64 static X25519 public key
//!     pub server_verifying_key: String,           // Base64 Ed25519 verification key
//!     pub server_ephemeral_public: String,        // Base64 ephemeral X25519 key
//!     pub server_signature: String,               // Ed25519 signature over keys
//!     pub stage_token: String,                    // HMAC binding Stage 1→2
//! }
//! ```
//!
//! **`ExchangeStage2Request`** — Received by server in Stage 2:
//! ```ignore
//! pub struct ExchangeStage2Request {
//!     pub stage_token: String,                    // From Stage 1 response
//!     pub client_public_key_b64: String,          // Client static X25519
//!     pub nonce: String,                          // 24 random bytes (base64)
//!     pub ciphertext: String,                     // Encrypted client keys
//! }
//! ```
//!
//! **`ExchangeStage2Response`** — Sent by server in Stage 2 response:
//! ```ignore
//! pub struct ExchangeStage2Response {
//!     pub encrypted_verifying_key: String,        // Server's Ed25519 key (encrypted)
//!     pub verifying_key_hmac: String,             // HMAC-SHA256 authentication
//!     pub kyber_ciphertext: String,               // Kyber-1024 encapsulated secret
//!     pub temp_jwt: String,                       // Temporary JWT (10 min validity)
//!     pub token_type: String,                     // "Bearer"
//!     pub expires_in: u64,                        // 600 seconds
//! }
//! ```
//!
//! **`TokenPair`** — OAuth2-style token response (access + refresh):
//! ```ignore
//! pub struct TokenPair {
//!     pub access_token: String,                   // JWT valid 15 minutes
//!     pub refresh_token: String,                  // JWT valid 7 days
//!     pub token_type: String,                     // "Bearer"
//!     pub expires_in: u64,                        // Seconds until access_token expires
//! }
//! ```
//!
//! **`EncryptedRequest`** — Client request structure (used by both server to receive):
//! ```ignore
//! pub struct EncryptedRequest {
//!     pub session_id: String,                     // UUID for O(1) server lookup
//!     pub nonce: String,                          // 24 random bytes (base64)
//!     pub ciphertext: String,                     // XSalsa20-Poly1305 encrypted payload
//!     pub timestamp: i64,                         // Unix timestamp (seconds)
//! }
//! ```
//!
//! **`EncryptedResponse`** — Server response structure:
//! ```ignore
//! pub struct EncryptedResponse {
//!     pub nonce: String,                          // 24 random bytes (base64)
//!     pub ciphertext: String,                     // Encrypted response payload
//!     pub signature: String,                      // Ed25519 signature over nonce || ciphertext
//!     pub timestamp: i64,                         // Unix timestamp (seconds)
//! }
//! ```
//!
//! **`Claims`** — JWT claims for session tokens:
//! ```ignore
//! pub struct Claims {
//!     pub sub: String,                            // Subject (session UUID)
//!     pub exp: usize,                             // Expiration time (Unix timestamp)
//!     pub iat: usize,                             // Issued at (Unix timestamp)
//!     pub token_type: String,                     // "access" or "refresh"
//! }
//! ```
//!
//! ### Server Key Functions
//!
//! **Initialization**:
//! ```ignore
//! impl SecuroServ {
//!     pub fn new() -> Self
//!     pub fn new_with_logger(logger: LoggerHandle) -> Self
//!     pub fn get_public_key_base64(&self) -> String
//!     pub fn get_verifying_key_base64(&self) -> String
//! }
//! ```
//!
//! **Key Exchange (Stage 1)**:
//! ```ignore
//! pub fn perform_exchange_stage1(&self) -> Result<ExchangeStage1Response, ServerError>
//! ```
//! Generates ephemeral X25519 keys, Ed25519 verifying key, and stage_token binding.
//!
//! **Key Exchange (Stage 2)**:
//! ```ignore
//! pub fn perform_exchange_stage2(&self, req: ExchangeStage2Request) 
//!     -> Result<ExchangeStage2Response, ServerError>
//! ```
//! Processes client's Stage 2 request, derives hybrid secret, encrypts server's verifying key,
//! and encapsulates Kyber shared secret.
//!
//! **Token Generation**:
//! ```ignore
//! pub fn generate_token_pair(&self, session_id: &Uuid) 
//!     -> Result<TokenPair, ServerError>
//! pub fn generate_temp_jwt(&self, session_id: &Uuid) 
//!     -> Result<String, ServerError>
//! ```
//!
//! ## Client Cryptography — Data Structures & Functions
//!
//! See module [`client::crypto`] for implementation.
//!
//! ### Client Data Structures
//!
//! **`SecuroClient`** — Main client crypto state (ephemeral + static keys, Kyber keypair):
//! ```ignore
//! pub struct SecuroClient {
//!     // Static X25519 keypair (persists across sessions)
//!     static_secret_key: SecretKey,
//!     static_public_key: PublicKey,
//!     
//!     // Ephemeral X25519 keypair (fresh per exchange)
//!     ephemeral_secret_key: SecretKey,
//!     ephemeral_public_key: PublicKey,
//!     
//!     // Ed25519 signing keypair
//!     signing_key: SigningKey,
//!     verifying_key: VerifyingKey,
//!     
//!     // Kyber-1024 post-quantum keypair
//!     kyber_secret_key: Vec<u8>,
//!     kyber_public_key: Vec<u8>,
//!     kyber_shared_secret: Option<Vec<u8>>,       // Decapsulated from server's ciphertext
//!     
//!     // Server keys (set during exchange)
//!     server_public_key: Option<PublicKey>,
//!     server_verifying_key: Option<VerifyingKey>,
//!     
//!     // Session state
//!     session_id: Option<String>,
//! }
//! ```
//!
//! **`EncryptedRequest`** — Request structure sent by client:
//! ```ignore
//! pub struct EncryptedRequest {
//!     pub session_id: String,                     // UUID for server lookup
//!     pub nonce: String,                          // 24 random bytes (base64)
//!     pub ciphertext: String,                     // XSalsa20-Poly1305 encrypted
//!     pub timestamp: i64,                         // Unix timestamp (seconds)
//! }
//! ```
//!
//! **`EncryptedResponse`** — Response received from server:
//! ```ignore
//! pub struct EncryptedResponse {
//!     pub nonce: String,
//!     pub ciphertext: String,
//!     pub signature: String,                      // Ed25519 signature for verification
//!     pub timestamp: i64,
//! }
//! ```
//!
//! ### Client Key Functions
//!
//! **Initialization**:
//! ```ignore
//! impl SecuroClient {
//!     pub fn new() -> Self
//!     pub fn new_with_logger(logger: LoggerHandle) -> Self
//! }
//! ```
//!
//! **Key Access**:
//! ```ignore
//! pub fn get_public_key_base64(&self) -> String
//! pub fn get_ephemeral_public_base64(&self) -> String
//! pub fn get_kyber_public_base64(&self) -> String
//! pub fn get_verifying_key_base64(&self) -> String
//! pub fn set_session_id(&mut self, session_id: String)
//! pub fn get_session_id(&self) -> Option<&str>
//! ```
//!
//! **Stage 2 Exchange**:
//! ```ignore
//! pub fn encrypt_client_keys_stage2(
//!     &mut self,
//!     server_public_key_b64: &str,
//!     nonce_b64: &str
//! ) -> Result<String, Box<dyn Error>>
//! pub fn process_stage2_response(&mut self, stage2_resp: &ExchangeStage2Response)
//!     -> Result<(), Box<dyn Error>>
//! pub fn decrypt_stage2_response(
//!     &mut self,
//!     encrypted_vk_b64: &str,
//!     kyber_ciphertext_b64: &str,
//!     shared_secret: &[u8]
//! ) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>>
//! ```
//!
//! **Kyber Operations**:
//! ```ignore
//! pub fn decapsulate_kyber(&mut self, kyber_ciphertext_b64: &str) 
//!     -> Result<(), Box<dyn Error>>
//! pub fn set_server_public_key(&mut self, server_public_key_b64: &str) 
//!     -> Result<(), Box<dyn Error>>
//! pub fn set_server_verifying_key(&mut self, server_verifying_key_b64: &str) 
//!     -> Result<(), Box<dyn Error>>
//! ```
//!
//! **Encryption & Decryption**:
//! ```ignore
//! pub fn encrypt_request(
//!     &self,
//!     payload: &[u8],
//!     shared_secret: &[u8]
//! ) -> Result<EncryptedRequest, Box<dyn Error>>
//! pub fn decrypt_response(
//!     &self,
//!     response: &EncryptedResponse,
//!     shared_secret: &[u8]
//! ) -> Result<Vec<u8>, Box<dyn Error>>
//! pub fn verify_server_signature_stage2(
//!     &self,
//!     message: &[u8],
//!     signature_b64: &str
//! ) -> Result<bool, Box<dyn Error>>
//! ```
//!
//! ## Documentation Resources
//!
//! - **Security Architecture** — See `/docs/SECURITY_ARCHITECTURE.md` for cryptographic stack details, algorithm specifications, and security rationale
//! - **Authentication Flow** — See `/docs/AUTHENTICATION_ARCHITECTURE.md` for HTTP routes and authentication protocol

pub mod logger;
pub mod tls;

pub mod client {
    pub mod crypto;
    pub mod pin;
}

pub mod server {
    pub mod crypto;
    pub mod pin;
}