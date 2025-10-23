use securo::client::crypto::{SecuroClient, EncryptedResponse};

#[derive(serde::Deserialize)]
pub struct RefreshResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

/// Refresh access token using refresh token (OAuth2 flow)
pub async fn refresh_access_token(
    client: &reqwest::Client,
    crypto: &mut SecuroClient,
    refresh_token: &str,
) -> Result<RefreshResponse, Box<dyn std::error::Error>> {
    tracing::info!("Refreshing access token using refresh token...");
    
    let session_id = crypto.get_session_id()
        .ok_or("Session ID not set")?;

    // Create encrypted request with refresh_token in payload
    let payload = serde_json::json!({
        "refresh_token": refresh_token
    });
    let encrypted_req = crypto.encrypt_request(session_id, payload)?;
    
    let resp = client
        .post("https://127.0.0.1:8443/api/refresh")
        .json(&encrypted_req)
        .send()
        .await?;
    
    if !resp.status().is_success() {
        let error_msg = format!("Failed to refresh token: Status {}", resp.status());
        tracing::error!("{}", error_msg);
        return Err(error_msg.into());
    }
    
    // Decrypt the response
    let encrypted_resp: EncryptedResponse = resp.json().await?;
    let decrypted_response = crypto.decrypt_response(&encrypted_resp)?;
    
    let refresh_resp = RefreshResponse {
        access_token: decrypted_response.get("access_token")
            .and_then(|t| t.as_str())
            .ok_or("access_token missing in response")?
            .to_string(),
        token_type: decrypted_response.get("token_type")
            .and_then(|t| t.as_str())
            .unwrap_or("Bearer")
            .to_string(),
        expires_in: decrypted_response.get("expires_in")
            .and_then(|t| t.as_u64())
            .unwrap_or(900),
    };
    
    // Update client with new access token
    crypto.set_session_id(refresh_resp.access_token.clone());
    
    tracing::info!("✅ Token refreshed successfully!");
    tracing::info!("New Access Token: {}...", &refresh_resp.access_token[..std::cmp::min(30, refresh_resp.access_token.len())]);
    tracing::info!("Token Type: {}", refresh_resp.token_type);
    tracing::info!("Expires in: {} seconds", refresh_resp.expires_in);
    
    Ok(refresh_resp)
}
