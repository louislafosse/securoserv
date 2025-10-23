mod modules {
    pub mod client;
    pub mod antidebug;
    pub mod auth;
    pub mod token;
    pub mod messaging;
    pub mod license;
}

use securo::client::crypto::SecuroClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    let mut _guard = None;

    if std::env::var("SERVER_LOG").unwrap_or_default() == "true" {
        let file_appender = tracing_appender::rolling::RollingFileAppender::new(
            tracing_appender::rolling::Rotation::DAILY,
            "./logs",
            "securo-client.log"
        );
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        tracing_subscriber::fmt()
            .with_writer(tracing_subscriber::fmt::writer::MakeWriterExt::and(non_blocking, std::io::stdout))
            .with_target(false)
            .with_env_filter("info")
            .with_timer(tracing_subscriber::fmt::time::ChronoLocal::new("%Y-%m-%dT%H:%M:%S".to_string()))
            .init();

        _guard = Some(guard);
    } else {
        tracing_subscriber::fmt()
            .with_writer(std::io::stdout)
            .with_target(false)
            .with_env_filter("info")
            .with_timer(tracing_subscriber::fmt::time::ChronoLocal::new("%Y-%m-%dT%H:%M:%S".to_string()))
            .init();
    }

    tracing::info!("Starting SecuroClient with certificate pinning and end-to-end encryption\n");

    // Get machine ID for anti-debug and ban system
    let machine_id = modules::antidebug::get_machine_id()?;
    tracing::info!("Machine ID: {}\n", machine_id);

    // Create pinned HTTP client
    let client = modules::client::create_pinned_client(include_bytes!("../../securoserv/cert.pem").to_vec())?;


    tracing::info!("Test 1: Testing server connection...");
    match client.get("https://127.0.0.1:8443/").send().await {
        Ok(resp) => {
            tracing::info!("✅ Connection successful! Status: {}", resp.status());
            if let Ok(body) = resp.text().await {
                tracing::info!("Response: {}\n", body);
            }
        }
        Err(e) => {
            tracing::error!("❌ Connection failed: {}", e);
            tracing::warn!("This is expected if:");
            tracing::warn!("   - Server is not running");
            tracing::warn!("   - Certificate doesn't match");
            tracing::warn!("   - Burp/mitmproxy is intercepting\n");
            return Err(e.into());
        }
    }

    tracing::info!("Test 2: Performing two-stage secure key exchange...");
    let mut crypto = SecuroClient::new();
    
    // Stage 1: Get server ephemeral key
    let stage1_response = modules::auth::exchange_keys_stage1(&client).await?;
    tracing::info!("✅ Stage 1: Received server ephemeral key");
    
    // Stage 2: Send encrypted client keys and complete exchange
    let exchange_response = modules::auth::exchange_keys_stage2(&client, &mut crypto, stage1_response).await?;
    tracing::info!("✅ Stage 2: Exchange completed");
    
    let temp_jwt = exchange_response.temp_jwt.clone();
    let session_id = crypto.get_session_id().unwrap().to_string();
    tracing::info!("Temp JWT (10 min): {}...", &temp_jwt[..std::cmp::min(30, temp_jwt.len())]);
    tracing::info!("");

    tracing::info!("Test 3: Creating license key via admin API...");
    let create_lic_req = serde_json::json!({ "session_id": session_id, "expires_in": 86400 });
    let lic_resp = client
        .post("https://127.0.0.1:8443/api/admin/create_license")
        .json(&create_lic_req)
        .send()
        .await?;

    if !lic_resp.status().is_success() {
        return Err(format!("Failed to create license: {}", lic_resp.status()).into());
    }

    let lic_json: serde_json::Value = lic_resp.json().await?;
    let license_key = lic_json.get("license_id")
        .and_then(|v| v.as_str())
        .ok_or("license_id missing")?;
    
    tracing::info!("License created: {}", license_key);
    tracing::info!("");

    // Send encrypted authentication with license key - get permanent tokens
    tracing::info!("Test 4: Sending encrypted authentication...");
    let auth_response = modules::auth::auth(&client, &crypto, license_key).await?;
    let access_token = auth_response.access_token.clone();
    let refresh_token = auth_response.refresh_token.clone();
    crypto.set_session_id(access_token.clone());  // Update session_id to permanent access token
    tracing::info!("Access Token: {}...", &access_token[..std::cmp::min(30, access_token.len())]);
    tracing::info!("Refresh Token: {}...", &refresh_token[..std::cmp::min(30, refresh_token.len())]);
    tracing::info!("");

    let monitor_client = client.clone();
    let monitor_session_id = access_token.clone();
    let monitor_machine_id = machine_id.clone();
    tokio::spawn(async move {
        modules::antidebug::debugger_monitor_task(monitor_client, monitor_session_id, monitor_machine_id).await;
    });
    tracing::info!("🔍 Debugger monitoring started in background\n");

    tracing::info!("Test 4: Sending encrypted message...");
    let response = modules::messaging::send_encrypted_message(
        &client,
        &crypto,
        "Hello from client! This is a secret message."
    ).await?;
    tracing::info!("✅ Message sent successfully");
    tracing::info!("Server response: {}\n", response);

    tracing::info!("Test 5: Sending second encrypted message...");
    let response = modules::messaging::send_encrypted_message(
        &client,
        &crypto,
        "Second message - authenticated by session ID!"
    ).await?;
    tracing::info!("✅ Message sent successfully");
    tracing::info!("Server response: {}\n", response);

    tracing::info!("Test 5: Requesting encrypted message from server...");
    let decrypted_message = modules::messaging::receive_encrypted_message(
        &client,
        &crypto,
        &access_token
    ).await?;
    tracing::info!("✅ Received and decrypted message from server");
    tracing::info!("Message: {}\n", decrypted_message);

    tracing::info!("Creating a license before the check...");
    let license_data = modules::license::create_license(
        &client,
        &session_id,
        Some(600) // 10 minutes in seconds
    ).await?;
    
    // Extract license_id from the response
    let license_id = license_data.get("license_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&session_id)
        .to_string();
    
    tracing::info!("✅ License created: {:?}\n", license_data);


    tracing::info!("Test 6: Checking license validity...");
    match modules::license::check_license(&client, &crypto, &license_id, &machine_id).await {
        Ok(result) => {
            tracing::info!("✅ License check result: {}\n", result);
        }
        Err(e) => {
            tracing::error!("License check failed: {}\n", e);
        }
    }


    tracing::info!("Test 7: Refreshing access token...");
    modules::token::refresh_access_token(&client, &mut crypto, &refresh_token).await?;
    tracing::info!("");

    tracing::info!("Test 8: Creating license (admin demo)...");
    match modules::license::create_license(&client, &session_id, None).await {
        Ok(lic_data) => {
            tracing::info!("✅ License created\n");
            // Store license_id for removal test
            let remove_lic_id = lic_data.get("license_id")
                .and_then(|v| v.as_str())
                .unwrap_or(&session_id);            

            tracing::info!("Test 9: Removing license (admin demo)...");
            match modules::license::remove_license(&client, remove_lic_id).await {
                Ok(result) => {
                    tracing::info!("✅ License removed: {}\n", result);
                }
                Err(e) => {
                    tracing::warn!("License removal failed (expected if not admin): {}\n", e);
                }
            }
        }
        Err(e) => {
            tracing::warn!("License creation failed (expected if not admin): {}\n", e);
        }
    }


    tracing::info!("Test 10: unauthenticating session...");
    modules::auth::unauth(&client, &crypto).await?;
    tracing::info!("");

    tracing::info!("✅ All tests completed successfully!");
    Ok(())
}
