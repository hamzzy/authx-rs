use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id:             Uuid,
    pub email:          String,
    pub email_verified: bool,
    pub created_at:     DateTime<Utc>,
    pub updated_at:     DateTime<Utc>,
    pub metadata:       serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct CreateUser {
    pub email:    String,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default)]
pub struct UpdateUser {
    pub email:          Option<String>,
    pub email_verified: Option<bool>,
    pub metadata:       Option<serde_json::Value>,
}
