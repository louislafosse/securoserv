// Database query functions for all tables
use diesel::prelude::*;
use crate::db::{DbPool, Session, License, Ban, Report, Message, AuditLog, schema::*};

// ==================== SESSION QUERIES ====================

#[allow(dead_code)]
pub fn insert_session(db: &DbPool, session: Session) -> Result<(), Box<dyn std::error::Error>> {
    use diesel::insert_into;
    
    let mut conn = db.lock().unwrap();
    insert_into(sessions::table)
        .values(&session)
        .execute(&mut *conn)?;
    
    Ok(())
}

#[allow(dead_code)]
pub fn get_session_by_uuid(db: &DbPool, session_uuid: &str) -> Result<Option<Session>, Box<dyn std::error::Error>> {
    use diesel::query_dsl::QueryDsl;
    
    let mut conn = db.lock().unwrap();
    let result = sessions::table
        .filter(sessions::session_uuid.eq(session_uuid))
        .first::<Session>(&mut *conn)
        .optional()?;
    
    Ok(result)
}

#[allow(dead_code)]
pub fn update_session_heartbeat(db: &DbPool, session_uuid: &str, timestamp: i64) -> Result<(), Box<dyn std::error::Error>> {
    use diesel::update;
    
    let mut conn = db.lock().unwrap();
    update(sessions::table.filter(sessions::session_uuid.eq(session_uuid)))
        .set(sessions::last_heartbeat.eq(timestamp))
        .execute(&mut *conn)?;
    
    Ok(())
}

#[allow(dead_code)]
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

// ==================== REPORT QUERIES ====================
#[allow(dead_code)]
pub fn insert_report(db: &DbPool, report: Report) -> Result<(), Box<dyn std::error::Error>> {
    use diesel::insert_into;
    
    let mut conn = db.lock().unwrap();
    insert_into(reports::table)
        .values(&report)
        .execute(&mut *conn)?;
    
    tracing::info!("✅ Report inserted: {} reported by {}", report.reported_session, report.reporter_session);
    Ok(())
}

#[allow(dead_code)]
pub fn get_open_reports(db: &DbPool) -> Result<Vec<Report>, Box<dyn std::error::Error>> {
    use diesel::query_dsl::QueryDsl;
    
    let mut conn = db.lock().unwrap();
    let results = reports::table
        .filter(reports::status.eq("open"))
        .load::<Report>(&mut *conn)?;
    
    Ok(results)
}

#[allow(dead_code)]
pub fn update_report_status(db: &DbPool, report_id: &str, status: &str) -> Result<(), Box<dyn std::error::Error>> {
    use diesel::update;
    
    let mut conn = db.lock().unwrap();
    update(reports::table.filter(reports::id.eq(report_id)))
        .set(reports::status.eq(status))
        .execute(&mut *conn)?;
    
    Ok(())
}

// ==================== MESSAGE QUERIES ====================

#[allow(dead_code)]
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

#[allow(dead_code)]
pub fn get_undelivered_messages(db: &DbPool, recipient: &str) -> Result<Vec<Message>, Box<dyn std::error::Error>> {
    use diesel::query_dsl::QueryDsl;
    
    let mut conn = db.lock().unwrap();
    let results = messages::table
        .filter(messages::recipient_session.eq(recipient))
        .filter(messages::is_delivered.eq(false))
        .load::<Message>(&mut *conn)?;
    
    Ok(results)
}

#[allow(dead_code)]
pub fn mark_message_delivered(db: &DbPool, message_id: &str, delivered_at: i64) -> Result<(), Box<dyn std::error::Error>> {
    use diesel::update;
    
    let mut conn = db.lock().unwrap();
    update(messages::table.filter(messages::id.eq(message_id)))
        .set((messages::is_delivered.eq(true), messages::delivered_at.eq(Some(delivered_at))))
        .execute(&mut *conn)?;
    
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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
