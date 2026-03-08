//! JWKS (JSON Web Key Set) for OIDC provider.

use authx_core::error::{AuthError, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};

/// JWKS document for the OIDC provider's signing key.
pub fn jwks_from_public_pem(public_pem: &[u8], kid: &str) -> Result<JwksDocument> {
    let pem_str = std::str::from_utf8(public_pem)
        .map_err(|_| AuthError::Internal("invalid PEM encoding".into()))?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_public_key_pem(pem_str)
        .map_err(|e| AuthError::Internal(format!("invalid Ed25519 public key: {e}")))?;
    let key_bytes = verifying_key.as_bytes();
    let x = URL_SAFE_NO_PAD.encode(key_bytes);
    let jwk = Jwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        kid: Some(kid.into()),
        x,
    };
    Ok(JwksDocument { keys: vec![jwk] })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksDocument {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    pub x: String,
}
