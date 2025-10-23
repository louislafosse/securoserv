use securo::client::crypto::{SecuroClient, EncryptedResponse};

/// Check license validity and ban status
pub async fn check_license(
    client: &reqwest::Client,
    crypto: &SecuroClient,
    license_id: &str,
    hwid: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    tracing::debug!("Checking license validity...");
    
    let session_id = crypto.get_session_id()
        .ok_or("Session ID not set")?;

    // Create encrypted request
    let payload = serde_json::json!({
        "license_id": license_id,
        "hwid": hwid
    });
    let encrypted_req = crypto.encrypt_request(session_id, payload)?;
    
    let resp = client
        .post("https://127.0.0.1:8443/api/check")
        .json(&encrypted_req)
        .send()
        .await?;
    
    if !resp.status().is_success() {
        let status = resp.status();
        let error_body = resp.text().await.unwrap_or_else(|_| "Unknown error".to_string());
        let error_msg = format!("License check failed: Status {} - {}", status, error_body);
        return Err(error_msg.into());
    }
    
    // Decrypt the response
    let encrypted_resp: EncryptedResponse = resp.json().await?;
    let decrypted_response = crypto.decrypt_response(&encrypted_resp)?;
    let response_text = decrypted_response.to_string();
    
    tracing::debug!("License check result: {}", response_text);
    
    Ok(response_text)
}

/// Create a license (admin operation)
pub async fn create_license(
    client: &reqwest::Client,
    temp_jwt_session_id: &str,
    expires_in: Option<u64>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    tracing::info!("Creating license for session...");
    

    let mut payload = serde_json::json!({"session_id": temp_jwt_session_id});
    if let Some(exp) = expires_in {
        payload["expires_in"] = serde_json::json!(exp);
    }
    
    let resp = client
        .post("https://127.0.0.1:8443/api/admin/create_license")
        .json(&payload)
        .send()
        .await?;
    
    if !resp.status().is_success() {
        let error_msg = format!("Failed to create license: Status {}", resp.status());
        tracing::error!("{}", error_msg);
        return Err(error_msg.into());
    }
    
    let license_data: serde_json::Value = resp.json().await?;
    tracing::info!("✅ License created successfully");
    tracing::info!("License data: {}", serde_json::to_string_pretty(&license_data)?);
    
    Ok(license_data)
}

/// Remove a license (admin operation)
pub async fn remove_license(
    client: &reqwest::Client,
    license_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    tracing::info!("Removing license: {}", license_id);
    
    let payload = serde_json::json!({"license_id": license_id});
    
    let resp = client
        .post("https://127.0.0.1:8443/api/admin/remove_license")
        .json(&payload)
        .send()
        .await?;
    
    if !resp.status().is_success() {
        let error_msg = format!("Failed to remove license: Status {}", resp.status());
        tracing::error!("{}", error_msg);
        return Err(error_msg.into());
    }
    
    let response_text = resp.text().await?;
    tracing::info!("✅ License removed: {}", response_text);
    
    Ok(response_text)
}
