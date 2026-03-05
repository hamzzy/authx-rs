use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── OAuth2 / OIDC Client ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClient {
    pub id: Uuid,
    pub client_id: String,
    /// SHA-256 hash of the client secret (like a password — never stored raw).
    pub secret_hash: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    /// Allowed OAuth2 grant types (e.g. "authorization_code", "refresh_token").
    pub grant_types: Vec<String>,
    /// Allowed response types (e.g. "code").
    pub response_types: Vec<String>,
    /// Space-separated allowed scopes (e.g. "openid profile email").
    pub allowed_scopes: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct CreateOidcClient {
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub allowed_scopes: String,
    /// SHA-256 hash of the client secret (empty for public clients).
    pub secret_hash: String,
}

// ── Authorization Code ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub id: Uuid,
    pub code_hash: String,
    pub client_id: String,
    pub user_id: Uuid,
    pub redirect_uri: String,
    pub scope: String,
    pub nonce: Option<String>,
    /// PKCE S256 code challenge (optional but recommended).
    pub code_challenge: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
}

#[derive(Debug, Clone)]
pub struct CreateAuthorizationCode {
    pub code_hash: String,
    pub client_id: String,
    pub user_id: Uuid,
    pub redirect_uri: String,
    pub scope: String,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub expires_at: DateTime<Utc>,
}

// ── Access / Refresh Tokens ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcToken {
    pub id: Uuid,
    pub token_hash: String,
    pub client_id: String,
    pub user_id: Uuid,
    pub scope: String,
    pub token_type: OidcTokenType,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OidcTokenType {
    Access,
    Refresh,
    DeviceAccess,
}

#[derive(Debug, Clone)]
pub struct CreateOidcToken {
    pub token_hash: String,
    pub client_id: String,
    pub user_id: Uuid,
    pub scope: String,
    pub token_type: OidcTokenType,
    pub expires_at: Option<DateTime<Utc>>,
}

// ── Device Authorization ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCode {
    pub id: Uuid,
    /// SHA-256 of the device_code sent to the device.
    pub device_code_hash: String,
    /// SHA-256 of the user_code shown on the device.
    pub user_code_hash: String,
    /// The raw user_code (short, human-typeable — e.g. "BDWD-HQPK").
    pub user_code: String,
    pub client_id: String,
    pub scope: String,
    pub expires_at: DateTime<Utc>,
    pub interval_secs: u32,
    pub authorized: bool,
    pub denied: bool,
    pub user_id: Option<Uuid>,
    pub last_polled_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct CreateDeviceCode {
    pub device_code_hash: String,
    pub user_code_hash: String,
    pub user_code: String,
    pub client_id: String,
    pub scope: String,
    pub expires_at: DateTime<Utc>,
    pub interval_secs: u32,
}

// ── SSO / OIDC Federation ─────────────────────────────────────────────────────

/// An external OIDC IdP configuration (e.g. corporate Okta, Azure AD).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcFederationProvider {
    pub id: Uuid,
    pub name: String,
    /// The OIDC issuer URL (used to discover .well-known/openid-configuration).
    pub issuer: String,
    pub client_id: String,
    /// AES-GCM encrypted client secret.
    pub secret_enc: String,
    pub scopes: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct CreateOidcFederationProvider {
    pub name: String,
    pub issuer: String,
    pub client_id: String,
    pub secret_enc: String,
    pub scopes: String,
}
