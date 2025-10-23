use actix_web::{http::StatusCode, web, HttpResponse};
use serde::Serialize;

use crate::license::{
    LicenseManager, BanManager
};
use securo::server::crypto::{SecuroServ, EncryptedRequest, ExchangeStage2Request};

/// Admin: create a license for a session_id
pub async fn admin_create_license(
    license_manager: web::Data<LicenseManager>,
    crypto: web::Data<SecuroServ>,
    req: web::Bytes,
) -> HttpResponse {

    if let Ok(encrypted_req) = serde_json::from_slice::<EncryptedRequest>(&req) {
        let (session_id, payload) = match crypto.decrypt_request(&encrypted_req) {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Failed to decrypt admin_create_license request: {:?}", e);
                e.log_security_event();
                return HttpResponse::Unauthorized().body("Decryption failed");
            }
        };

        tracing::info!("Admin create license request (encrypted) from session: {}", &session_id[..std::cmp::min(40, session_id.len())]);

        let expires_in = payload.get("expires_in").and_then(|v| v.as_u64());

        let lic = license_manager.create_license(&session_id, expires_in);
        
        let response = serde_json::json!(lic);
        match crypto.encrypt_response(&session_id, response) {
            Ok(encrypted_resp) => {
                tracing::info!("License created, response encrypted");
                HttpResponse::Ok().json(encrypted_resp)
            }
            Err(e) => {
                tracing::error!("Failed to encrypt admin_create_license response: {:?}", e);
                HttpResponse::InternalServerError().body("Encryption failed")
            }
        }
    } else {

        match serde_json::from_slice::<serde_json::Value>(&req) {
            Ok(plain_req) => {
                let session_id = match plain_req.get("session_id").and_then(|v| v.as_str()) {
                    Some(s) => s,
                    None => return HttpResponse::BadRequest().body("session_id required"),
                };

                let expires_in = plain_req.get("expires_in").and_then(|v| v.as_u64());

                tracing::info!("Admin create license request (plain) from session: {}", &session_id[..std::cmp::min(40, session_id.len())]);

                let lic = license_manager.create_license(session_id, expires_in);
                HttpResponse::Ok().json(lic)
            }
            Err(e) => {
                tracing::error!("Failed to parse admin_create_license request: {:?}", e);
                HttpResponse::BadRequest().body("Invalid request format")
            }
        }
    }
}


pub async fn admin_remove_license(
    license_manager: web::Data<LicenseManager>,
    req: web::Json<serde_json::Value>,
) -> HttpResponse {
    let session_id = req.get("session_id").and_then(|v| v.as_str());
    let license_id = req.get("license_id").and_then(|v| v.as_str());

    let key_to_remove = license_id.or(session_id);

    match key_to_remove {
        Some(key) => {
            if license_manager.remove_license(key) {
                HttpResponse::Ok().body("removed")
            } else {
                HttpResponse::NotFound().body("not found")
            }
        }
        None => HttpResponse::BadRequest().body("license_id or session_id required"),
    }
}

pub async fn check_license(
    license_manager: web::Data<LicenseManager>,
    ban_manager: web::Data<BanManager>,
    crypto: web::Data<SecuroServ>,
    req: web::Bytes,
) -> HttpResponse {

    if let Ok(encrypted_req) = serde_json::from_slice::<EncryptedRequest>(&req) {
        let (session_id, payload) = match crypto.decrypt_request(&encrypted_req) {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Failed to decrypt check_license request: {:?}", e);
                e.log_security_event();
                return HttpResponse::Unauthorized().body("Decryption failed");
            }
        };

        tracing::info!("Check license request (encrypted) from session: {}", &session_id[..std::cmp::min(40, session_id.len())]);

        let license_id = payload.get("license_id").and_then(|v| v.as_str());
        
        if license_id.is_none() {
            let error_resp = serde_json::json!({"error": "license_id required"});
            return match crypto.encrypt_response(&session_id, error_resp) {
                Ok(encrypted_err) => HttpResponse::BadRequest().json(encrypted_err),
                Err(_) => HttpResponse::BadRequest().body("license_id required"),
            };
        }

        let hwid = match payload.get("hwid").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => {
                let error_resp = serde_json::json!({"error": "hwid required"});
                return match crypto.encrypt_response(&session_id, error_resp) {
                    Ok(encrypted_err) => HttpResponse::BadRequest().json(encrypted_err),
                    Err(_) => HttpResponse::BadRequest().body("hwid required"),
                };
            }
        };

        // Check if banned
        if ban_manager.is_banned((session_id.as_str(), hwid)) {
            let error_resp = serde_json::json!({"status": "banned"});
            return match crypto.encrypt_response(&session_id, error_resp) {
                Ok(encrypted_resp) => HttpResponse::Forbidden().json(encrypted_resp),
                Err(_) => HttpResponse::Forbidden().body("banned"),
            };
        }

        // Check license validity
        let is_valid = license_id.map(|lid| license_manager.check_license(lid)).unwrap_or(false);

        let response = serde_json::json!({
            "status": if is_valid { "valid" } else { "invalid or expired" }
        });

        match crypto.encrypt_response(&session_id, response) {
            Ok(encrypted_resp) => {
                let status_code = if is_valid { StatusCode::OK } else { StatusCode::FORBIDDEN };
                HttpResponse::build(status_code).json(encrypted_resp)
            }
            Err(e) => {
                tracing::error!("Failed to encrypt check_license response: {:?}", e);
                HttpResponse::InternalServerError().body("Encryption failed")
            }
        }
    } else {

        match serde_json::from_slice::<serde_json::Value>(&req) {
            Ok(plain_req) => {
                let session_id = plain_req.get("session_id").and_then(|v| v.as_str());
                let license_id = plain_req.get("license_id").and_then(|v| v.as_str());
                
                if session_id.is_none() && license_id.is_none() {
                    return HttpResponse::BadRequest().body("session_id or license_id required");
                }

                let hwid = match plain_req.get("hwid").and_then(|v| v.as_str()) {
                    Some(h) => h,
                    None => return HttpResponse::BadRequest().body("hwid required"),
                };

                // Check if banned first (using session_id if available)
                if let Some(sid) = session_id
                    && ban_manager.is_banned((sid, hwid)) {
                        return HttpResponse::Forbidden().body("banned");
                    }

                // Check license validity - try license_id first, then fall back to session_id
                let is_valid = if let Some(lid) = license_id {
                    license_manager.check_license(lid)
                } else if let Some(sid) = session_id {
                    license_manager.check_license(sid)
                } else {
                    false
                };

                if is_valid {
                    HttpResponse::Ok().body("valid")
                } else {
                    HttpResponse::Forbidden().body("invalid or expired")
                }
            }
            Err(e) => {
                tracing::error!("Failed to parse check_license request: {:?}", e);
                HttpResponse::BadRequest().body("Invalid request format")
            }
        }
    }
}

/// Report debugger detection from client: bans a session-id reported by client
pub async fn report(
    ban_manager: web::Data<BanManager>,
    req: web::Json<serde_json::Value>,
) -> HttpResponse {
    let session_id = match req.get("session_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return HttpResponse::BadRequest().body("session_id required"),
    };

    let hwid = match req.get("hwid").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return HttpResponse::BadRequest().body("hwid required"),
    };

    ban_manager.ban((session_id, hwid), "client-reported debugger");
    HttpResponse::Ok().body("banned")
}

/// Stage 1 of secure key exchange - Server sends ephemeral key
/// Server responds with: server_public_key, server_ephemeral_public, server_signature
pub async fn exchange_stage1(
    crypto: web::Data<SecuroServ>,
) -> HttpResponse {
    match crypto.perform_exchange_stage1() {
        Ok(response) => {
            tracing::info!("✅ Exchange Stage 1 completed");
            HttpResponse::Ok().json(response)
        }
        Err(e) => {
            tracing::error!("Exchange Stage 1 failed: {:?}", e);
            e.log_security_event();
            HttpResponse::build(StatusCode::from_u16(e.status_code()).unwrap()).body(e.to_string())
        }
    }
}

/// Stage 2 of secure key exchange - Client sends their public key
/// Client sends client_public_key_b64 and receives encrypted exchange response
pub async fn exchange_stage2(
    crypto: web::Data<SecuroServ>,
    body: web::Bytes,
) -> HttpResponse {
    // Parse the request
    let req: ExchangeStage2Request = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to parse stage2 request: {}", e);
            return HttpResponse::BadRequest().body("Invalid request format");
        }
    };
    
    // Process the stage 2 exchange
    match crypto.perform_exchange_stage2(req) {
        Ok(response) => {
            tracing::info!("✅ Exchange Stage 2 completed");
            HttpResponse::Ok().json(response)
        }
        Err(e) => {
            tracing::error!("Exchange Stage 2 failed: {:?}", e);
            e.log_security_event();
            HttpResponse::build(StatusCode::from_u16(e.status_code()).unwrap()).body(e.to_string())
        }
    }
}

/// Authentication - validates license, returns permanent access & refresh tokens
pub async fn auth(
    crypto: web::Data<SecuroServ>,
    req: web::Json<EncryptedRequest>,
    license_manager: web::Data<LicenseManager>,
) -> HttpResponse {
    // Decrypt the request - extracts session_id from payload
    let (session_id, payload) = match crypto.decrypt_request(&req) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to decrypt auth request: {:?}", e);
            e.log_security_event();
            return HttpResponse::Unauthorized().body("Decryption failed");
        }
    };

    tracing::info!("Auth request from session: {}", &session_id[..std::cmp::min(40, session_id.len())]);

    // License key is required for authentication
    let license_key = match payload.get("license_key").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => {
            let error_resp = serde_json::json!({"error": "license_key required"});
            return match crypto.encrypt_response(&session_id, error_resp) {
                Ok(encrypted_err) => HttpResponse::Forbidden().json(encrypted_err),
                Err(_) => HttpResponse::Forbidden().body("license_key required"),
            };
        }
    };

    tracing::info!("Validating license_key: {}", license_key);

    // Verify license exists
    if !license_manager.check_license(license_key) {
        tracing::warn!("Invalid or missing license_key: {}", license_key);
        let error_resp = serde_json::json!({"error": "invalid license_key"});
        return match crypto.encrypt_response(&session_id, error_resp) {
            Ok(encrypted_err) => HttpResponse::Forbidden().json(encrypted_err),
            Err(_) => HttpResponse::Forbidden().body("invalid license_key"),
        };
    }

    // Parse temp_jwt to get session UUID (verify it's valid and not expired)
    let session_uuid = match crypto.validate_exchange_token(&session_id) {
        Ok(uuid) => {
            tracing::info!("Exchange token validated for session: {}", uuid);
            uuid
        }
        Err(e) => {
            // If temp_jwt expired or invalid, reject
            tracing::warn!("Expired or invalid temp_jwt: {:?}", e);
            let error_resp = serde_json::json!({"error": "temp_jwt expired or invalid"});
            return match crypto.encrypt_response(&session_id, error_resp) {
                Ok(encrypted_err) => HttpResponse::Unauthorized().json(encrypted_err),
                Err(_) => HttpResponse::Unauthorized().body("temp_jwt expired or invalid"),
            };
        }
    };

    tracing::info!("Processing authenticated session with license: {}", license_key);

    // Generate permanent tokens
    match crypto.generate_token_pair(&session_uuid) {
        Ok(token_pair) => {
            #[derive(Serialize)]
            struct AuthSuccessResponse {
                access_token: String,
                refresh_token: String,
                token_type: String,
                expires_in: u64,
            }

            let response = AuthSuccessResponse {
                access_token: token_pair.access_token,
                refresh_token: token_pair.refresh_token,
                token_type: token_pair.token_type,
                expires_in: token_pair.expires_in,
            };

            tracing::info!("Authentication successful for session: {}", session_uuid);
            
            match crypto.encrypt_response(&session_id, serde_json::to_value(&response).unwrap_or(serde_json::json!({}))) {
                Ok(encrypted_resp) => HttpResponse::Ok().json(encrypted_resp),
                Err(e) => {
                    tracing::error!("Failed to encrypt auth response: {:?}", e);
                    e.log_security_event();
                    HttpResponse::InternalServerError().body("Encryption failed")
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to generate tokens: {:?}", e);
            e.log_security_event();
            HttpResponse::build(StatusCode::from_u16(e.status_code()).unwrap()).body(e.to_string())
        }
    }
}

/// Receive encrypted message (POST)
pub async fn receive_encrypted(
    crypto: web::Data<SecuroServ>,
    req: web::Json<EncryptedRequest>,
) -> HttpResponse {
    // Decrypt the request
    let (session_id, payload) = match crypto.decrypt_request(&req) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to decrypt message: {:?}", e);
            e.log_security_event();

            return HttpResponse::Unauthorized().body("Decryption failed");
        }
    };

    tracing::debug!("Received encrypted message from session: {}", &session_id[..std::cmp::min(40, session_id.len())]);


    let message = payload.get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("Message received");

    // Encrypt the response with the received message (server echoes it back)
    let response_payload = serde_json::json!({
        "message": message,
        "status": "received"
    });

    match crypto.encrypt_response(&session_id, response_payload) {
        Ok(encrypted_resp) => {
            tracing::debug!("Encrypted response sent successfully");
            HttpResponse::Ok().json(encrypted_resp)
        }
        Err(e) => {
            tracing::error!("Failed to encrypt response: {:?}", e);
            e.log_security_event();
            HttpResponse::InternalServerError().body("Encryption failed")
        }
    }
}

/// Get encrypted message (POST)
pub async fn get_encrypted(
    crypto: web::Data<SecuroServ>,
    req: web::Json<EncryptedRequest>,
) -> HttpResponse {
    let (session_id, _payload) = match crypto.decrypt_request(&req) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to decrypt get_encrypted request: {:?}", e);
            e.log_security_event();
            return HttpResponse::Unauthorized().body("Decryption failed");
        }
    };

    tracing::debug!("Get encrypted message request from session: {}", &session_id[..std::cmp::min(40, session_id.len())]);

    let response_payload = serde_json::json!({
        "message": "Hello from server"
    });

    match crypto.encrypt_response(&session_id, response_payload) {
        Ok(encrypted_resp) => {
            tracing::debug!("Encrypted response sent successfully");
            HttpResponse::Ok().json(encrypted_resp)
        }
        Err(e) => {
            tracing::error!("Failed to encrypt response: {:?}", e);
            e.log_security_event();
            HttpResponse::InternalServerError().body("Encryption failed")
        }
    }
}

/// Send an encrypted message to a session (via encrypted request/response)
pub async fn send_encrypted(
    crypto: web::Data<SecuroServ>,
    req: web::Json<EncryptedRequest>,
) -> HttpResponse {
    let (session_id, payload) = match crypto.decrypt_request(&req) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to decrypt send_encrypted request: {:?}", e);
            e.log_security_event();
            return HttpResponse::Unauthorized().body("Decryption failed");
        }
    };

    tracing::debug!("Send encrypted message request from session: {}", &session_id[..std::cmp::min(40, session_id.len())]);

    let message = payload.get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("Hello from server");

    let response_payload = serde_json::json!({
        "message": message,
        "status": "sent"
    });

    match crypto.encrypt_response(&session_id, response_payload) {
        Ok(encrypted_resp) => {
            tracing::debug!("Encrypted message sent successfully");
            HttpResponse::Ok().json(encrypted_resp)
        }
        Err(e) => {
            tracing::error!("Failed to encrypt send_encrypted response: {:?}", e);
            e.log_security_event();
            HttpResponse::InternalServerError().body("Encryption failed")
        }
    }
}

/// Unauthenticate a client session (by access token)
pub async fn unauth(
    crypto: web::Data<SecuroServ>,
    req: web::Json<EncryptedRequest>,
) -> HttpResponse {
    let (session_id, _payload) = match crypto.decrypt_request(&req) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to decrypt unauth request: {:?}", e);
            e.log_security_event();
            return HttpResponse::Unauthorized().body("Decryption failed");
        }
    };

    let session_uuid = match crypto.validate_access_token(&session_id) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("Invalid access token in unauth: {:?}", e);
            e.log_security_event();
            
            let error_resp = serde_json::json!({"error": e.to_string()});
            return match crypto.encrypt_response(&session_id, error_resp) {
                Ok(encrypted_err) => HttpResponse::Unauthorized().json(encrypted_err),
                Err(_) => HttpResponse::Unauthorized().body(e.to_string()),
            };
        }
    };

    // Encrypt response BEFORE removing session
    let response = serde_json::json!({"status": "Session unauthenticated successfully"});
    let encrypted_resp = match crypto.encrypt_response(&session_id, response) {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("Failed to encrypt unauth response: {:?}", e);
            e.log_security_event();
            return HttpResponse::InternalServerError().body("Encryption failed");
        }
    };

    match crypto.unauth(&session_uuid.to_string()) {
        Ok(_) => {
            tracing::info!("Session unauthenticated successfully");
            HttpResponse::Ok().json(encrypted_resp)
        }
        Err(e) => {
            tracing::error!("Failed to unauthenticate session: {:?}", e);
            e.log_security_event();
            HttpResponse::InternalServerError().json(encrypted_resp)
        }
    }
}

/// Refresh access token using refresh token (OAuth2-style)
pub async fn refresh_token(
    crypto: web::Data<SecuroServ>,
    req: web::Json<EncryptedRequest>,
) -> HttpResponse {
    let (session_id, payload) = match crypto.decrypt_request(&req) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to decrypt refresh token request: {:?}", e);
            e.log_security_event();
            return HttpResponse::Unauthorized().body("Decryption failed");
        }
    };

    tracing::info!("Refresh token request from session: {}", &session_id[..std::cmp::min(40, session_id.len())]);

    let refresh_token = match payload.get("refresh_token").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return HttpResponse::BadRequest().body("refresh_token required in encrypted payload"),
    };

    let session_uuid = match crypto.validate_refresh_token(refresh_token) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("Invalid refresh token: {:?}", e);
            e.log_security_event();
            return HttpResponse::build(StatusCode::from_u16(e.status_code()).unwrap()).body(e.to_string());
        }
    };

    match crypto.generate_token_pair(&session_uuid) {
        Ok(tp) => {
            #[derive(Serialize)]
            struct RefreshResponse {
                access_token: String,
                token_type: String,
                expires_in: u64,
            }
            let resp = RefreshResponse { access_token: tp.access_token, token_type: tp.token_type, expires_in: tp.expires_in };
            
            match crypto.encrypt_response(&session_id, serde_json::to_value(&resp).unwrap_or(serde_json::json!({}))) {
                Ok(encrypted_resp) => {
                    tracing::info!("Refresh token successful, response encrypted");
                    HttpResponse::Ok().json(encrypted_resp)
                }
                Err(e) => {
                    tracing::error!("Failed to encrypt refresh token response: {:?}", e);
                    e.log_security_event();
                    HttpResponse::InternalServerError().body("Encryption failed")
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to generate tokens: {:?}", e);
            e.log_security_event();
            HttpResponse::build(StatusCode::from_u16(e.status_code()).unwrap()).body(e.to_string())
        }
    }
}
