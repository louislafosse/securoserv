use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct License {
    pub license_id: String,
    pub session_id: String,
    pub issued_at: u64,
    pub expiration_date: Option<u64>,
}

#[derive(Clone)]
pub struct LicenseManager {
    inner: Arc<Mutex<HashMap<String, License>>>,
}

impl LicenseManager {
    pub fn new(path: PathBuf) -> Self {
        let mut map = HashMap::new();
        if path.exists()
            && let Ok(mut f) = File::open(&path) {
                tracing::warn!("Loading licenses from {:?}", path);
                let mut s = String::new();
                if f.read_to_string(&mut s).is_ok()
                    && let Ok(m) = serde_json::from_str::<HashMap<String, License>>(&s) {
                        map = m;
                    }
            }
        LicenseManager {
            inner: Arc::new(Mutex::new(map)),
        }
    }

    pub fn create_license(&self, session_id: &str, expires_in: Option<u64>) -> License {
        let now = chrono::Utc::now().timestamp() as u64;
        let license_id = Uuid::new_v4().to_string();
        let lic = License {
            license_id,
            session_id: session_id.to_string(),
            issued_at: now,
            expiration_date: Some(now + expires_in.unwrap_or(0)),
        };
        // Store licenses keyed by the license_id so callers can validate using the
        // license token returned by the admin API (UUID). Previously we keyed
        // by session_id which made checks using the license_id fail.
        if let Ok(mut map) = self.inner.lock() {
            map.insert(lic.license_id.clone(), lic.clone());
        }
        lic
    }

    /// Remove a license by its license_id (UUID). Returns true if removed.
    pub fn remove_license(&self, license_id: &str) -> bool {
        if let Ok(mut map) = self.inner.lock() {
            let removed = map.remove(license_id).is_some();
            return removed;
        }
        false
    }

    /// Check whether a license exists and is not expired.
    /// The input is the license_id (UUID) returned by `create_license`.
    pub fn check_license(&self, license_id: &str) -> bool {
        if let Ok(map) = self.inner.lock()
            && let Some(lic) = map.get(license_id) {
                if let Some(exp) = lic.expiration_date {
                    let now = chrono::Utc::now().timestamp() as u64;
                    return now <= exp;
                }
                return true;
            }
        false
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanEntry {
    pub ban_id: String,
    pub session_id: String,
    pub hwid: String,
    pub reason: String,
    pub banned_at: u64,
}

#[derive(Clone)]
pub struct BanManager {
    inner: Arc<Mutex<Vec<BanEntry>>>,
}

impl BanManager {
    pub fn new(path: PathBuf) -> Self {
        let mut bans = Vec::new();
        if path.exists()
            && let Ok(mut f) = File::open(&path) {
                tracing::warn!("Loading bans from {:?}", path);
                let mut s = String::new();
                if f.read_to_string(&mut s).is_ok()
                    && let Ok(b) = serde_json::from_str::<Vec<BanEntry>>(&s) {
                        bans = b;
                    }
            }
        BanManager {
            inner: Arc::new(Mutex::new(bans)),
        }
    }

    pub fn ban(&self, ids: (&str, &str), reason: &str) {
        let (session_id, hwid) = ids;
        let now = chrono::Utc::now().timestamp() as u64;
        let ban_id = Uuid::new_v4().to_string();
        tracing::warn!("Ban {} - session {} (hwid {}) reason={} at {}", ban_id, session_id, hwid, reason, now);

        let entry = BanEntry {
            ban_id,
            session_id: session_id.to_string(),
            hwid: hwid.to_string(),
            reason: reason.to_string(),
            banned_at: now,
        };
        
        if let Ok(mut list) = self.inner.lock() {
            // Check if already banned by session_id or hwid
            if !list.iter().any(|e| e.session_id == session_id || e.hwid == hwid) {
                list.push(entry);
            }
        }
    }

    pub fn is_banned(&self, ids: (&str, &str)) -> bool {
        let (session_id, hwid) = ids;
        if let Ok(list) = self.inner.lock() {
            return list.iter().any(|e| e.session_id == session_id || e.hwid == hwid);
        }
        false
    }
}
