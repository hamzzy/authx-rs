use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthAccount {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_user_id: String,
    /// AES-256-GCM encrypted access token (base64url encoded ciphertext).
    pub access_token_enc: String,
    /// AES-256-GCM encrypted refresh token, if the provider issues one.
    pub refresh_token_enc: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct UpsertOAuthAccount {
    pub user_id: Uuid,
    pub provider: String,
    pub provider_user_id: String,
    pub access_token_enc: String,
    pub refresh_token_enc: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}
