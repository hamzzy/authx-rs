use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    Password,
    Passkey,
    OauthToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id:              Uuid,
    pub user_id:         Uuid,
    pub kind:            CredentialKind,
    pub credential_hash: String,
    pub metadata:        serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct CreateCredential {
    pub user_id:         Uuid,
    pub kind:            CredentialKind,
    pub credential_hash: String,
    pub metadata:        Option<serde_json::Value>,
}
