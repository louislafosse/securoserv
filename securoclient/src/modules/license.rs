use securo::client::crypto::{SecuroClient, EncryptedResponse};

/// Bootstrap: Authenticate with admin license key to get admin session
/// Returns the (access_token, refresh_token) tuple
pub async fn bootstrap_authenticate(
    client: &reqwest::Client,
    crypto: &SecuroClient,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    tracing::info!("Bootstrap: Authenticating with admin license key...");
    
    let admin_license_key = "b7f4c2e9-8d3a-4f1b-9e2c-5a6d7f8e9c1a-admin-bootstrap-key";
    let session_id = crypto.get_session_id()
        .ok_or("Session ID not set")?;

    let payload = serde_json::json!({
        "license_key": admin_license_key
    });
    
    // Encrypt the request with exchange token (which is valid for /auth)
    let encrypted_req = crypto.encrypt_request(session_id, payload)?;
    
    let resp = client
        .post("https://127.0.0.1:8443/api/auth")
        .json(&encrypted_req)
        .send()
        .await?;
    
    if !resp.status().is_success() {
        let error_msg = format!("Failed to bootstrap authenticate: Status {}", resp.status());
        tracing::error!("{}", error_msg);
        return Err(error_msg.into());
    }
    
    // Decrypt the response
    let encrypted_resp: EncryptedResponse = resp.json().await?;
    let response_data = crypto.decrypt_response(&encrypted_resp)?;
    
    let access_token = response_data.get("access_token")
        .and_then(|v| v.as_str())
        .ok_or("No access_token in response")?
        .to_string();
    
    let refresh_token = response_data.get("refresh_token")
        .and_then(|v| v.as_str())
        .ok_or("No refresh_token in response")?
        .to_string();
    
    tracing::info!("✅ Bootstrap authentication successful - session is now admin");
    
    Ok((access_token, refresh_token))
}

/// Create a license (admin operation - server validates if session is admin)
pub async fn create_license(
    client: &reqwest::Client,
    crypto: &SecuroClient,
    expires_in: Option<u64>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    tracing::info!("Creating license for session...");
    
    let session_id = crypto.get_session_id()
        .ok_or("Session ID not set")?;

    let mut payload = serde_json::json!({});
    if let Some(exp) = expires_in {
        payload["expires_in"] = serde_json::json!(exp);
    }
    
    let encrypted_req = crypto.encrypt_request(session_id, payload)?;
    
    let resp = client
        .post("https://127.0.0.1:8443/api/admin/create_license")
        .json(&encrypted_req)
        .send()
        .await?;
    
    if !resp.status().is_success() {
        let error_msg = format!("Failed to create license: Status {}", resp.status());
        tracing::error!("{}", error_msg);
        return Err(error_msg.into());
    }
    
    let encrypted_resp: EncryptedResponse = resp.json().await?;
    let license_data = crypto.decrypt_response(&encrypted_resp)?;
    
    Ok(license_data)
}

/// Remove a license (admin operation)
/// Remove a license (admin operation - server validates if session is admin)
pub async fn remove_license(
    client: &reqwest::Client,
    crypto: &SecuroClient,
    license_key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let session_id = crypto.get_session_id()
        .ok_or("Session ID not set")?;
    
    let payload = serde_json::json!({
        "license_key": license_key,
    });
    
    let encrypted_req = crypto.encrypt_request(session_id, payload)?;
    
    let resp = client
        .post("https://127.0.0.1:8443/api/admin/remove_license")
        .json(&encrypted_req)
        .send()
        .await?;
    
    if !resp.status().is_success() {
        let error_msg = format!("Failed to remove license: Status {}", resp.status());
        tracing::error!("{}", error_msg);
        return Err(error_msg.into());
    }
    
    let encrypted_resp: EncryptedResponse = resp.json().await?;
    let response_data = crypto.decrypt_response(&encrypted_resp)?;
    
    let response_text = serde_json::to_string(&response_data)?;
    
    Ok(response_text)
}

/// Check if a license is valid
pub async fn check_license(
    client: &reqwest::Client,
    crypto: &SecuroClient,
    license_key: &str,
    hwid: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let session_id = crypto.get_session_id()
        .ok_or("Session ID not set")?;
    
    let payload = serde_json::json!({
        "license_key": license_key,
        "hwid": hwid
    });
    
    let encrypted_req = crypto.encrypt_request(session_id, payload)?;
    
    let resp = client
        .post("https://127.0.0.1:8443/api/check")
        .json(&encrypted_req)
        .send()
        .await?;
    
    if !resp.status().is_success() {
        let error_msg = format!("License check failed: Status {}", resp.status());
        tracing::error!("{}", error_msg);
        return Err(error_msg.into());
    }
    
    let encrypted_resp: EncryptedResponse = resp.json().await?;
    let response_data = crypto.decrypt_response(&encrypted_resp)?;
    
    let is_valid = response_data.get("valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    
    Ok(is_valid.to_string())
}
