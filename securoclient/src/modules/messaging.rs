use securo::client::crypto::{SecuroClient, EncryptedResponse};

/// Send encrypted message to server
pub async fn send_encrypted_message(
    client: &reqwest::Client,
    crypto: &SecuroClient,
    plaintext: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    tracing::debug!("Sending encrypted message to server...");
    
    let session_id = crypto.get_session_id()
        .ok_or("Session ID not set")?;


    let payload = serde_json::json!({"message": plaintext});
    let encrypted_req = crypto.encrypt_request(session_id, payload)?;
    
    let resp = client
        .post("https://127.0.0.1:8443/api/encrypted")
        .json(&encrypted_req)
        .send()
        .await?;
    
    if !resp.status().is_success() {
        let error_msg = format!("Failed to send message: Status {}", resp.status());
        tracing::error!("{}", error_msg);
        return Err(error_msg.into());
    }
    

    let encrypted_resp: EncryptedResponse = resp.json().await?;
    let decrypted_response = crypto.decrypt_response(&encrypted_resp)?;
    let response_text = decrypted_response.to_string();
    
    tracing::debug!("Message sent successfully");
    
    Ok(response_text)
}

/// Request encrypted message from server
pub async fn receive_encrypted_message(
    client: &reqwest::Client,
    crypto: &SecuroClient,
    _session_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    tracing::debug!("Requesting encrypted message from server...");
    
    let session_id = crypto.get_session_id()
        .ok_or("Session ID not set")?;


    let payload = serde_json::json!({"request": "get_message"});
    let encrypted_req = crypto.encrypt_request(session_id, payload)?;
    
    // Note: For GET with encrypted body, we use POST to /api/encrypted/get endpoint
    // Alternatively, we can keep using the query parameter approach for backward compatibility
    // For now, we'll create a wrapper that encrypts the session_id in the request body
    let resp = client
        .post("https://127.0.0.1:8443/api/encrypted/get")
        .json(&encrypted_req)
        .send()
        .await?;
    
    if !resp.status().is_success() {
        let error_msg = format!("Failed to get message: Status {}", resp.status());
        tracing::error!("{}", error_msg);
        return Err(error_msg.into());
    }
    

    let encrypted_resp: EncryptedResponse = resp.json().await?;
    let decrypted_response = crypto.decrypt_response(&encrypted_resp)?;
    

    let message = decrypted_response.get("message")
        .and_then(|m| m.as_str())
        .unwrap_or(&decrypted_response.to_string())
        .to_string();
    
    tracing::debug!("Received and decrypted message from server");
    
    Ok(message)
}
