use std::collections::HashSet;
use std::sync::RwLock;
use uuid::Uuid;

/// Tracks which sessions have admin privileges
#[derive(Default)]
pub struct AdminSessions {
    sessions: RwLock<HashSet<Uuid>>,
}

impl AdminSessions {
    /// Mark a session as having admin privileges
    pub fn mark_as_admin(&self, session_uuid: Uuid) {
        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(session_uuid);
        tracing::debug!("Session {} marked as admin", session_uuid);
    }

    /// Check if a session has admin privileges
    pub fn is_admin(&self, session_uuid: &Uuid) -> bool {
        let sessions = self.sessions.read().unwrap();
        sessions.contains(session_uuid)
    }

    /// Remove admin privileges from a session
    pub fn remove(&self, session_uuid: &Uuid) {
        let mut sessions = self.sessions.write().unwrap();
        sessions.remove(session_uuid);
        tracing::debug!("Session {} removed from admin sessions", session_uuid);
    }
}
