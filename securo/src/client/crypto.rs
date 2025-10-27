use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    PublicKey, SalsaBox, SecretKey,
};
use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Verifier};
use rand::rngs::OsRng as RandOsRng;
use pqc_kyber::{keypair, decapsulate};
use std::time::{SystemTime, UNIX_EPOCH};
use hmac::{Hmac, Mac};
use sha2::Sha256;

const KYBER_1024_CIPHERTEXT_SIZE: usize = 1568;  // Kyber-1024 encapsulation produces exactly 1568 bytes

/// Message structure for encrypted communication
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub session_id: String,        // UUID - identifies the client session
    pub nonce: String,              // 24 random bytes
    pub ciphertext: String,         // contains encrypted JSON payload
    pub signature: String,          // Ed25519 signature over (session_id || nonce || ciphertext)
    pub timestamp: i64,
}

/// Encrypted request: client includes session_id for O(1) server-side lookup
/// Used for all authenticated API calls after /api/auth
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedRequest {
    pub session_id: String,         // Client's session UUID - enables O(1) server lookup
    pub nonce: String,
    pub ciphertext: String,
    pub timestamp: i64,             // Unix timestamp (seconds) - for TTL validation
}

/// Encrypted response: all content is encrypted
/// Server responds with encrypted data that client must decrypt
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedResponse {
    pub nonce: String,
    pub ciphertext: String,
    pub signature: String,          // Ed25519 signature over (nonce || ciphertext)
    pub timestamp: i64,
}

/// Client crypto state (session-based - generates ephemeral keys and stores session ID)
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct SecuroClient {
    // Static X25519 keypair (persists across sessions)
    static_secret_key: SecretKey,
    static_public_key: PublicKey,
    
    // Ephemeral X25519 keypair (fresh for each exchange)
    ephemeral_secret_key: SecretKey,
    ephemeral_public_key: PublicKey,
    
    // Ed25519 keypair for signatures
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    
    // POST-QUANTUM: Kyber-1024 keypair
    kyber_secret_key: Vec<u8>,
    kyber_public_key: Vec<u8>,
    kyber_shared_secret: Option<Vec<u8>>,  // Decapsulated shared secret from server
    
    server_public_key: Option<PublicKey>,
    server_verifying_key: Option<VerifyingKey>,  // Server's Ed25519 key for response verification
    session_id: Option<String>,
}

impl SecuroClient {
    /// Create a client crypto instance with fresh X25519 (static + ephemeral), Ed25519, and Kyber-1024 keypairs
    pub fn new() -> Self {
        let static_secret_key = SecretKey::generate(&mut OsRng);
        let static_public_key = static_secret_key.public_key();
        
        let ephemeral_secret_key = SecretKey::generate(&mut OsRng);
        let ephemeral_public_key = ephemeral_secret_key.public_key();
        
        let signing_key = SigningKey::generate(&mut RandOsRng);
        let verifying_key = signing_key.verifying_key();
        
        let mut rng = RandOsRng;
        let kyber_kp = keypair(&mut rng).expect("Failed to generate Kyber keypair");

        tracing::info!("Client ephemeral keypair generated");
        tracing::info!("✅ Kyber-1024 keypair generated (post-quantum)");

        Self {
            static_secret_key,
            static_public_key,
            ephemeral_secret_key,
            ephemeral_public_key,
            signing_key,
            verifying_key,
            kyber_secret_key: kyber_kp.secret.to_vec(),
            kyber_public_key: kyber_kp.public.to_vec(),
            kyber_shared_secret: None,
            server_public_key: None,
            server_verifying_key: None,
            session_id: None,
        }
    }

    /// Get the client's Ed25519 verifying key (public) as base64
    pub fn get_verifying_key_base64(&self) -> String {
        BASE64_URL_SAFE.encode(self.verifying_key.as_bytes())
    }

    /// Get the client's ephemeral X25519 public key as base64
    pub fn get_ephemeral_public_base64(&self) -> String {
        BASE64_URL_SAFE.encode(self.ephemeral_public_key.as_bytes())
    }

    /// Get the client's Kyber-1024 public key as base64 (POST-QUANTUM)
    pub fn get_kyber_public_base64(&self) -> String {
        BASE64_URL_SAFE.encode(&self.kyber_public_key)
    }

    /// Set the session ID received from registration
    pub fn set_session_id(&mut self, session_id: String) {
        tracing::info!("Session ID set: {}", session_id);
        self.session_id = Some(session_id);
    }

    /// Get the session ID
    pub fn get_session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Get the client's static X25519 public key as base64
    pub fn get_public_key_base64(&self) -> String {
        BASE64_URL_SAFE.encode(self.static_public_key.as_bytes())
    }

    /// Set the server's public key
    pub fn set_server_public_key(&mut self, server_public_key_b64: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Decode the server's public key
        let server_public_key_bytes = BASE64_URL_SAFE.decode(server_public_key_b64)?;
        
        if server_public_key_bytes.len() != 32 {
            return Err("Invalid public key length".into());
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&server_public_key_bytes);
        self.server_public_key = Some(PublicKey::from(key_array));

        tracing::info!("Server public key set");
        Ok(())
    }

    /// Set the server's Ed25519 verifying key for response signature verification
    pub fn set_server_verifying_key(&mut self, server_verifying_key_b64: &str) -> Result<(), Box<dyn std::error::Error>> {
        let server_verifying_key_bytes = BASE64_URL_SAFE.decode(server_verifying_key_b64)?;
        
        if server_verifying_key_bytes.len() != 32 {
            return Err("Invalid verifying key length".into());
        }

        let verifying_key = VerifyingKey::from_bytes(
            server_verifying_key_bytes[..32].as_ref().try_into()?
        )?;
        
        self.server_verifying_key = Some(verifying_key);
        Ok(())
    }

    /// Decapsulate Kyber ciphertext to derive post-quantum shared secret
    pub fn decapsulate_kyber(&mut self, kyber_ciphertext_b64: &str) -> Result<(), Box<dyn std::error::Error>> {
        if kyber_ciphertext_b64.is_empty() {
            return Ok(());  // No Kyber ciphertext provided
        }
        
        let ciphertext = BASE64_URL_SAFE.decode(kyber_ciphertext_b64)?;
        
        // SECURITY: Validate ciphertext length - Kyber-1024 produces exactly 1568 bytes
        // An attacker modifying the ciphertext length could cause decapsulation to fail
        // in unexpected ways, or could exploit edge cases in the decapsulation algorithm.
        // By validating length upfront, we ensure the ciphertext hasn't been tampered with.
        if ciphertext.len() != KYBER_1024_CIPHERTEXT_SIZE {
            tracing::warn!(
                "⚠️  SECURITY: Invalid Kyber ciphertext length: got {} bytes, expected {} bytes. Possible MITM!",
                ciphertext.len(),
                KYBER_1024_CIPHERTEXT_SIZE
            );
            return Err(format!(
                "Invalid Kyber ciphertext length: got {}, expected {}",
                ciphertext.len(),
                KYBER_1024_CIPHERTEXT_SIZE
            ).into());
        }
        
        let shared_secret = decapsulate(&ciphertext, &self.kyber_secret_key)
            .map_err(|_| "Failed to decapsulate Kyber ciphertext")?;
        
        self.kyber_shared_secret = Some(shared_secret.to_vec());
        Ok(())
    }

    /// Verify the HMAC of the encrypted verifying key using the Kyber shared secret
    pub fn verify_verifying_key_hmac(
        &self,
        encrypted_verifying_key_b64: &str,
        expected_hmac_b64: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(kyber_ss) = &self.kyber_shared_secret {
            let encrypted_bytes = BASE64_URL_SAFE.decode(encrypted_verifying_key_b64)?;

            // Compute HMAC of encrypted verifying key using Kyber shared secret
            let mut mac = Hmac::<Sha256>::new_from_slice(kyber_ss)
                .map_err(|_| "Failed to create HMAC")?;
            mac.update(&encrypted_bytes);
            
            // Decode and verify expected HMAC against computed HMAC
            let expected_hmac_bytes = BASE64_URL_SAFE.decode(expected_hmac_b64)?;
            mac.verify_slice(&expected_hmac_bytes)
                .map_err(|_| "Verifying key HMAC verification failed")?;
            
            Ok(())
        } else {
            Err("Kyber shared secret not available for HMAC verification".into())
        }
    }

    /// Create a shared secret box with the server (uses static secret key)
    fn create_box(&self) -> Result<SalsaBox, Box<dyn std::error::Error>> {
        let server_public_key = self.server_public_key.as_ref()
            .ok_or("Server public key not set")?;
        
        Ok(SalsaBox::new(server_public_key, &self.static_secret_key))
    }

    /// Get the client's static X25519 secret key
    pub fn get_static_secret_key(&self) -> &SecretKey {
        &self.static_secret_key
    }

    /// Decrypt the server's verifying key (encrypted with client's static public key)
    pub fn decrypt_verifying_key(&self, encrypted_vk_b64: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let salsa_box = self.create_box()?;

        let encrypted_bytes = BASE64_URL_SAFE.decode(encrypted_vk_b64)?;
        
        // The server sends: nonce (24 bytes) + ciphertext
        if encrypted_bytes.len() < 24 {
            return Err("Invalid encrypted verifying key length".into());
        }

        let nonce_bytes = &encrypted_bytes[..24];
        let ciphertext = &encrypted_bytes[24..];

        let mut nonce_array = [0u8; 24];
        nonce_array.copy_from_slice(nonce_bytes);
        let nonce = crypto_box::Nonce::from(nonce_array);

        // Decrypt
        let plaintext = salsa_box
            .decrypt(&nonce, ciphertext)
            .map_err(|e| format!("Failed to decrypt verifying key: {:?}", e))?;

        Ok(plaintext)
    }

    /// Encrypt a request with session_id sent in plaintext
    /// The session_id is not encrypted, allowing the server to route to correct session immediately
    /// The payload (including sensitive data) is encrypted
    pub fn encrypt_request(
        &self,
        session_id: &str,
        payload: serde_json::Value,
    ) -> Result<EncryptedRequest, Box<dyn std::error::Error>> {
        let salsa_box = self.create_box()?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
            
        let inner_payload = serde_json::json!({
            "payload": payload
        });

        let plaintext = serde_json::to_vec(&inner_payload)?;

        // Generate a random nonce
        let nonce = SalsaBox::generate_nonce(&mut OsRng);

        // Encrypt
        let ciphertext = salsa_box
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| format!("Encryption failed: {:?}", e))?;

        Ok(EncryptedRequest {
            session_id: session_id.to_string(),
            nonce: BASE64_URL_SAFE.encode(&nonce[..]),
            ciphertext: BASE64_URL_SAFE.encode(&ciphertext),
            timestamp: now,
        })
    }

    /// Decrypt an encrypted response from the server
    pub fn decrypt_response(
        &self,
        response: &EncryptedResponse,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {        
        // Verify signature first if server key is set
        if let Some(verifying_key) = &self.server_verifying_key {
            // Reconstruct the message that was signed: nonce || ciphertext
            let mut sig_message = Vec::new();
            sig_message.extend_from_slice(response.nonce.as_bytes());
            sig_message.extend_from_slice(b"||");
            sig_message.extend_from_slice(response.ciphertext.as_bytes());
            
            // Decode and verify signature
            let signature_bytes = BASE64_URL_SAFE.decode(&response.signature)?;
            if signature_bytes.len() != 64 {
                return Err("Invalid signature length".into());
            }
            
            let mut sig_array = [0u8; 64];
            sig_array.copy_from_slice(&signature_bytes);
            let signature = Signature::from_bytes(&sig_array);
            
            verifying_key.verify(&sig_message, &signature)?;
        }
        
        // Validate response timestamp freshness (TTL validation)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        let time_diff = (now - response.timestamp).abs();
        const TTL_WINDOW: i64 = 60;  // 60 second window for response freshness
        if time_diff > TTL_WINDOW {
            return Err(format!(
                "Response timestamp validation failed: time difference {} seconds exceeds TTL window of {} seconds",
                time_diff, TTL_WINDOW
            ).into());
        }
        
        let salsa_box = self.create_box()?;

        let nonce_bytes = BASE64_URL_SAFE.decode(&response.nonce)?;
        let ciphertext = BASE64_URL_SAFE.decode(&response.ciphertext)?;

        if nonce_bytes.len() != 24 {
            return Err("Invalid nonce length".into());
        }

        let mut nonce_array = [0u8; 24];
        nonce_array.copy_from_slice(&nonce_bytes);
        let nonce = crypto_box::Nonce::from(nonce_array);

        // Decrypt
        let plaintext = salsa_box
            .decrypt(&nonce, ciphertext.as_ref())
            .map_err(|e| format!("Decryption failed: {:?}", e))?;

        let plaintext_str = String::from_utf8(plaintext)?;
        let response_payload: serde_json::Value = serde_json::from_str(&plaintext_str)?;

        Ok(response_payload)
    }
}

impl Default for SecuroClient {
    fn default() -> Self {
        Self::new()
    }
}
