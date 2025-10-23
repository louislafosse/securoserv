use securo::client::crypto::{SecuroClient, EncryptedResponse};
use base64::engine::Engine as _;
use ed25519_dalek::Verifier;
use crypto_box::aead::{Aead, AeadCore};

#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ExchangeRequest {
    pub client_public_key: String,
    pub client_ephemeral_public: String,
    pub client_verifying_key: String,
    pub client_kyber_public: String,      // POST-QUANTUM: Kyber-1024 public key
}

/// Stage 1 response from server
#[derive(serde::Deserialize, Debug)]
pub struct ExchangeStage1Response {
    pub server_x25519_public: String,
    pub server_verifying_key: String,
    pub server_ephemeral_public: String,
    pub server_signature: String,
    pub stage_token: String,            // HMAC token binding Stage 1 to Stage 2
}

/// Stage 2 request - Client sends encrypted keys
#[derive(serde::Serialize)]
pub struct ExchangeStage2Request {
    pub stage_token: String,            // HMAC token from Stage 1 response - prevents session fixation
    pub client_public_key_b64: String,
    pub nonce: String,
    pub ciphertext: String,
}

/// Stage 2 response - Server completes exchange
#[derive(serde::Deserialize, Debug)]
pub struct ExchangeStage2Response {
    pub nonce: String,
    pub ciphertext: String,
}

#[allow(dead_code)]
#[derive(serde::Deserialize, Debug)]
pub struct ExchangeResponse {
    pub server_public_key: String,
    pub server_ephemeral_public: String,
    pub server_signature: String,
    pub encrypted_verifying_key: String,
    pub verifying_key_hmac: String,       // HMAC-SHA256 of encrypted_verifying_key using Kyber shared secret
    pub kyber_ciphertext: String,         // POST-QUANTUM: Kyber-1024 encapsulated secret
    pub temp_jwt: String,              // 10-minute temporary JWT for auth phase
    pub token_type: String,
    pub expires_in: u64,
}

#[allow(dead_code)]
#[derive(serde::Deserialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

/// Client requests server's ephemeral key
#[allow(dead_code)]
pub async fn exchange_keys_stage1(
    client: &reqwest::Client,
) -> Result<ExchangeStage1Response, Box<dyn std::error::Error>> {
    tracing::info!("Exchange Stage 1: Requesting server ephemeral key...");
    
    let resp = client
        .get("https://127.0.0.1:8443/api/exchange/stage1")
        .send()
        .await?;
    
    if !resp.status().is_success() {
        let error_msg = format!("Exchange Stage 1 failed: Status {}", resp.status());
        tracing::error!("{}", error_msg);
        return Err(error_msg.into());
    }
    
    let stage1_resp: ExchangeStage1Response = resp.json().await?;
    tracing::info!("✅ Stage 1 complete: Received server ephemeral key");
    
    Ok(stage1_resp)
}

/// Client sends encrypted keys and completes key agreement
pub async fn exchange_keys_stage2(
    client: &reqwest::Client,
    crypto: &mut SecuroClient,
    stage1_response: ExchangeStage1Response,
) -> Result<ExchangeResponse, Box<dyn std::error::Error>> {
    tracing::info!("Exchange Stage 2: Sending encrypted client keys...");
    
    // Set server's X25519 public key (for regular encryption after exchange)
    crypto.set_server_public_key(&stage1_response.server_x25519_public)?;
    
    // Verify server's signature on (server_verifying_key || server_ephemeral)
    let server_verifying_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&stage1_response.server_verifying_key)?;
    let server_ephemeral_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&stage1_response.server_ephemeral_public)?;
    let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&stage1_response.server_signature)?;
    
    use ed25519_dalek::{VerifyingKey, Signature};
    
    // The server_verifying_key IS the Ed25519 verifying key (32 bytes)
    if server_verifying_bytes.len() < 32 {
        return Err("Server verifying key too short".into());
    }
    
    let verifying_key = VerifyingKey::from_bytes(
        &server_verifying_bytes[..32].try_into()?
    )?;
    
    if signature_bytes.len() != 64 {
        return Err("Invalid signature length".into());
    }
    
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&signature_bytes);
    let signature = Signature::from_bytes(&sig_bytes);
    
    let mut sig_message = Vec::new();
    sig_message.extend_from_slice(&server_verifying_bytes);
    sig_message.extend_from_slice(&server_ephemeral_bytes);
    
    verifying_key.verify(&sig_message, &signature)
        .map_err(|e| format!("Signature verification failed: {:?}", e))?;
    tracing::info!("✅ Server signature verified");
    
    // Create payload with client keys (plain JSON that will be encrypted)
    let client_keys_payload = serde_json::json!({
        "client_verifying_key": crypto.get_verifying_key_base64(),
        "client_kyber_public": crypto.get_kyber_public_base64(),
    });
    
    // Encrypt using the server's ephemeral public key that was sent in stage 1
    // This creates a fresh ephemeral shared secret for this exchange
    use crypto_box::{SalsaBox, PublicKey as CryptoBoxPublicKey};
    
    let server_ephemeral_pub = {
        if server_ephemeral_bytes.len() != 32 {
            return Err("Invalid server ephemeral key length".into());
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&server_ephemeral_bytes);
        CryptoBoxPublicKey::from(key_array)
    };
    
    // Use client's static secret to create box with server's ephemeral public
    let client_static_secret = crypto.get_static_secret_key();
    let salsa_box = SalsaBox::new(&server_ephemeral_pub, client_static_secret);
    
    let nonce = SalsaBox::generate_nonce(&mut rand::rngs::OsRng);
    let plaintext = client_keys_payload.to_string();
    let ciphertext = salsa_box.encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| "Encryption failed")?;
    
    // For Stage 2, send client keys back to server
    // The server will decrypt using its stored ephemeral secret from Stage 1
    let stage2_req = ExchangeStage2Request {
        stage_token: stage1_response.stage_token,  // Include stage_token to bind Stage 1 to Stage 2
        client_public_key_b64: crypto.get_public_key_base64(),
        nonce: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&nonce[..]),
        ciphertext: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&ciphertext),
    };
    
    let resp = client
        .post("https://127.0.0.1:8443/api/exchange/stage2")
        .json(&stage2_req)
        .send()
        .await?;
    
    if !resp.status().is_success() {
        let error_msg = format!("Exchange Stage 2 failed: Status {}", resp.status());
        let body = resp.text().await.unwrap_or_default();
        tracing::error!("{} - {}", error_msg, body);
        return Err(error_msg.into());
    }
    
    let stage2_resp: ExchangeStage2Response = resp.json().await?;
    
    // Decrypt stage 2 response using the same ephemeral shared secret
    let nonce_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&stage2_resp.nonce)?;
    let ciphertext_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&stage2_resp.ciphertext)?;
    
    if nonce_bytes.len() != 24 {
        return Err("Invalid nonce length in response".into());
    }
    
    let mut nonce_array = [0u8; 24];
    nonce_array.copy_from_slice(&nonce_bytes);
    let response_nonce = crypto_box::Nonce::from(nonce_array);
    
    let plaintext_response = salsa_box.decrypt(&response_nonce, ciphertext_bytes.as_ref())
        .map_err(|_| "Response decryption failed")?;
    
    let response_json: serde_json::Value = serde_json::from_slice(&plaintext_response)?;
    
    let temp_jwt = response_json.get("temp_jwt")
        .and_then(|v| v.as_str())
        .ok_or("Missing temp_jwt in response")?
        .to_string();
    
    crypto.set_session_id(temp_jwt.clone());
    
    // Decapsulate Kyber ciphertext for post-quantum security
    let kyber_ciphertext = response_json.get("kyber_ciphertext").and_then(|v| v.as_str()).unwrap_or("");
    if !kyber_ciphertext.is_empty() {
        crypto.decapsulate_kyber(kyber_ciphertext)?;
    }
    
    tracing::info!("✅ Exchange Stage 2 complete");
    tracing::info!("Temp JWT (10 min): {}...", &temp_jwt[..std::cmp::min(30, temp_jwt.len())]);
    
    Ok(ExchangeResponse {
        server_public_key: stage1_response.server_x25519_public,
        server_ephemeral_public: stage1_response.server_ephemeral_public,
        server_signature: stage1_response.server_signature,
        encrypted_verifying_key: String::new(),
        verifying_key_hmac: String::new(),
        kyber_ciphertext: kyber_ciphertext.to_string(),
        temp_jwt,
        token_type: "Bearer".to_string(),
        expires_in: 600,
    })
}

/// Step 2: Send encrypted authentication with license key
/// Returns permanent access & refresh tokens
pub async fn auth(
    client: &reqwest::Client,
    crypto: &SecuroClient,
    license_key: &str,
) -> Result<AuthResponse, Box<dyn std::error::Error>> {
    tracing::info!("Sending encrypted authentication with license key");
    
    let session_id = crypto.get_session_id()
        .ok_or("Session ID not set")?;
    
    let auth_payload = serde_json::json!({
        "license_key": license_key,
    });

    let encrypted_req = crypto.encrypt_request(session_id, auth_payload)?;

    let resp = client
        .post("https://127.0.0.1:8443/api/auth")
        .json(&encrypted_req)
        .send()
        .await?;
    
    if !resp.status().is_success() {
        let error_msg = format!("Authentication failed: Status {}", resp.status());
        tracing::error!("{}", error_msg);
        return Err(error_msg.into());
    }
    
    let encrypted_resp: EncryptedResponse = resp.json().await?;
    let decrypted_value = crypto.decrypt_response(&encrypted_resp)?;
    let auth_resp: AuthResponse = serde_json::from_value(decrypted_value)?;
    
    tracing::info!("Authentication successful!");
    tracing::info!("Access Token: {}...", &auth_resp.access_token[..std::cmp::min(30, auth_resp.access_token.len())]);
    tracing::info!("Refresh Token: {}...", &auth_resp.refresh_token[..std::cmp::min(30, auth_resp.refresh_token.len())]);
    
    Ok(auth_resp)
}

/// Unauth session when done - plain JSON format
pub async fn unauth(
    client: &reqwest::Client,
    crypto: &SecuroClient,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("Unauthenticating session...");

    let session_id = crypto.get_session_id()
        .ok_or("Session ID not set")?;

    let unauth_payload = serde_json::json!({});
    
    let encrypted_req = crypto.encrypt_request(session_id, unauth_payload)?;
    
    let resp = client
        .post("https://127.0.0.1:8443/api/unauth")
        .json(&encrypted_req)
        .send()
        .await?;
    
    if !resp.status().is_success() {
        tracing::error!("Failed to unauthenticate: Status {}", resp.status());
        return Err(format!("Unauthentication failed: Status {}", resp.status()).into());
    }
    
    let encrypted_resp: EncryptedResponse = resp.json().await?;
    let decrypted_value = crypto.decrypt_response(&encrypted_resp)?;
    
    tracing::info!("✅ Session unauthenticated successfully!");
    tracing::info!("Server response: {}", decrypted_value);
    
    Ok(())
}
