// Database models and queries for Securoserv
use diesel::prelude::*;
use super::schema::*;

#[derive(Insertable, Queryable, Clone, Debug)]
#[diesel(table_name = sessions)]
pub struct Session {
    pub id: String,                    // UUID
    pub session_uuid: String,          // Session UUID from key exchange
    pub license_key: String,           // License UUID
    pub hardware_id: Option<String>,   // Hardware identifier for ban checking
    pub client_public_key: Vec<u8>,    // Client's X25519 public key (32 bytes)
    pub client_verifying_key: String,  // Client's Ed25519 verifying key (base64)
    pub client_kyber_public: String,   // Client's Kyber-1024 public key (base64)
    pub created_at: i64,               // Unix timestamp
    pub last_heartbeat: i64,           // Last activity timestamp
    pub is_authenticated: bool,        // true after /api/auth, false after /api/unauth
}

#[derive(Insertable, Queryable, Clone, Debug)]
#[diesel(table_name = licenses)]
pub struct License {
    pub id: String,                    // UUID
    pub license_key: String,           // Unique license identifier
    pub created_at: i64,               // Unix timestamp
    pub expires_at: i64,               // Expiration timestamp
    pub is_revoked: bool,              // true if license has been removed
    pub max_connections: i32,          // Maximum concurrent sessions
    pub license_type: String,          // "standard", "premium", "enterprise"
}

#[derive(Insertable, Queryable, Clone, Debug)]
#[diesel(table_name = bans)]
pub struct Ban {
    pub id: String,                    // UUID
    pub banned_entity: String,         // Either session UUID or hardware ID
    pub ban_type: String,              // "session" or "hardware"
    pub reason: String,                // Reason for ban
    pub created_at: i64,               // Unix timestamp
    pub banned_by: Option<String>,     // Admin that issued the ban
}

#[derive(Insertable, Queryable, Clone, Debug)]
#[diesel(table_name = reports)]
pub struct Report {
    pub id: String,                    // UUID
    pub reporter_session: String,      // Session UUID of reporter
    pub reported_session: String,      // Session UUID being reported
    pub reason: String,                // Report reason
    pub evidence: Option<String>,      // Additional evidence
    pub created_at: i64,               // Unix timestamp
    pub status: String,                // "open", "resolved", "dismissed"
}

#[derive(Insertable, Queryable, Clone, Debug)]
#[diesel(table_name = messages)]
pub struct Message {
    pub id: String,                    // UUID
    pub sender_session: String,        // Session UUID of sender
    pub recipient_session: Option<String>,  // Session UUID of recipient (if directed)
    pub content: String,               // Encrypted message content
    pub created_at: i64,               // Unix timestamp
    pub is_delivered: bool,            // true after retrieval
    pub delivered_at: Option<i64>,     // Timestamp of delivery
}

#[derive(Insertable, Queryable, Clone, Debug)]
#[diesel(table_name = audit_logs)]
pub struct AuditLog {
    pub id: String,                    // UUID
    pub session_uuid: Option<String>,  // Session UUID (None for pre-auth events)
    pub event_type: String,            // "auth", "unauth", "key_exchange", "ban", "license_revoke"
    pub event_data: String,            // JSON string with event details
    pub created_at: i64,               // Unix timestamp
    pub ip_address: Option<String>,    // Client IP (if available)
}
