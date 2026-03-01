use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub device_info: serde_json::Value,
    pub ip_address: String,
    pub org_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct CreateSession {
    pub user_id: Uuid,
    pub token_hash: String,
    pub device_info: serde_json::Value,
    pub ip_address: String,
    pub org_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
}
