// Database query functions for all tables
use diesel::prelude::*;
use crate::db::{DbPool, Session, License, Ban, Message, AuditLog, schema::*};

// ==================== SESSION QUERIES ====================

pub fn insert_session(db: &DbPool, session: Session) -> Result<(), Box<dyn std::error::Error>> {
    use diesel::insert_into;
    
    let mut conn = db.lock().unwrap();
    insert_into(sessions::table)
        .values(&session)
        .execute(&mut *conn)?;
    
    Ok(())
}

#[allow(unused)]
pub fn get_session_by_uuid(db: &DbPool, session_uuid: &str) -> Result<Option<Session>, Box<dyn std::error::Error>> {
    use diesel::query_dsl::QueryDsl;
    
    let mut conn = db.lock().unwrap();
    let result = sessions::table
        .filter(sessions::session_uuid.eq(session_uuid))
        .first::<Session>(&mut *conn)
        .optional()?;
    
    Ok(result)
}

#[allow(unused)]
pub fn update_session_authenticated(db: &DbPool, session_uuid: &str, is_authenticated: bool) -> Result<(), Box<dyn std::error::Error>> {
    use diesel::update;
    
    let mut conn = db.lock().unwrap();
    update(sessions::table.filter(sessions::session_uuid.eq(session_uuid)))
        .set(sessions::is_authenticated.eq(is_authenticated))
        .execute(&mut *conn)?;
    
    Ok(())
}

// ==================== LICENSE QUERIES ====================

pub fn insert_license(db: &DbPool, license: License) -> Result<(), Box<dyn std::error::Error>> {
    use diesel::insert_into;
    
    let mut conn = db.lock().unwrap();
    insert_into(licenses::table)
        .values(&license)
        .execute(&mut *conn)?;
    
    Ok(())
}

pub fn get_license_by_key(db: &DbPool, license_key: &str) -> Result<Option<License>, Box<dyn std::error::Error>> {
    use diesel::query_dsl::QueryDsl;
    
    let mut conn = db.lock().unwrap();
    let result = licenses::table
        .filter(licenses::license_key.eq(license_key))
        .first::<License>(&mut *conn)
        .optional()?;
    
    Ok(result)
}

pub fn revoke_license(db: &DbPool, license_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    use diesel::update;
    
    let mut conn = db.lock().unwrap();
    update(licenses::table.filter(licenses::license_key.eq(license_key)))
        .set(licenses::is_revoked.eq(true))
        .execute(&mut *conn)?;
    
    Ok(())
}

// ==================== BAN QUERIES ====================

pub fn insert_ban(db: &DbPool, ban: Ban) -> Result<(), Box<dyn std::error::Error>> {
    use diesel::insert_into;
    
    let mut conn = db.lock().unwrap();
    insert_into(bans::table)
        .values(&ban)
        .execute(&mut *conn)?;
    
    Ok(())
}

pub fn is_entity_banned(db: &DbPool, banned_entity: &str) -> Result<bool, Box<dyn std::error::Error>> {
    use diesel::query_dsl::QueryDsl;
    
    let mut conn = db.lock().unwrap();
    let result = bans::table
        .filter(bans::banned_entity.eq(banned_entity))
        .first::<Ban>(&mut *conn)
        .optional()?;
    
    Ok(result.is_some())
}

// ==================== MESSAGE QUERIES ====================

pub fn insert_message(db: &DbPool, message: Message) -> Result<(), Box<dyn std::error::Error>> {
    use diesel::insert_into;
    
    let mut conn = db.lock().unwrap();
    insert_into(messages::table)
        .values(&message)
        .execute(&mut *conn)?;
    
    tracing::info!("✅ Message inserted: {} -> {}", message.sender_session, 
        message.recipient_session.as_ref().unwrap_or(&"broadcast".to_string()));
    Ok(())
}

// ==================== AUDIT LOG QUERIES ====================

pub fn insert_audit_log(db: &DbPool, log: AuditLog) -> Result<(), Box<dyn std::error::Error>> {
    use diesel::insert_into;
    
    let mut conn = db.lock().unwrap();
    insert_into(audit_logs::table)
        .values(&log)
        .execute(&mut *conn)?;
    
    Ok(())
}

#[allow(unused)]
pub fn get_audit_logs_by_type(db: &DbPool, event_type: &str, limit: i64) -> Result<Vec<AuditLog>, Box<dyn std::error::Error>> {
    use diesel::query_dsl::QueryDsl;
    
    let mut conn = db.lock().unwrap();
    let results = audit_logs::table
        .filter(audit_logs::event_type.eq(event_type))
        .order_by(audit_logs::created_at.desc())
        .limit(limit)
        .load::<AuditLog>(&mut *conn)?;
    
    Ok(results)
}

#[allow(unused)]
pub fn get_session_audit_logs(db: &DbPool, session_uuid: &str, limit: i64) -> Result<Vec<AuditLog>, Box<dyn std::error::Error>> {
    use diesel::query_dsl::QueryDsl;
    
    let mut conn = db.lock().unwrap();
    let results = audit_logs::table
        .filter(audit_logs::session_uuid.eq(session_uuid))
        .order_by(audit_logs::created_at.desc())
        .limit(limit)
        .load::<AuditLog>(&mut *conn)?;
    
    Ok(results)
}
