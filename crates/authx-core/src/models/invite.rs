use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    pub id:          Uuid,
    pub org_id:      Uuid,
    pub email:       String,
    pub role_id:     Uuid,
    /// SHA-256 hash of the raw token (raw is returned to caller once).
    pub token_hash:  String,
    pub expires_at:  DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct CreateInvite {
    pub org_id:     Uuid,
    pub email:      String,
    pub role_id:    Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
}
