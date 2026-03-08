use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use uuid::Uuid;

use crate::error::{AuthError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

pub struct TokenSigner {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl TokenSigner {
    pub fn from_ed25519_pem(private_pem: &[u8], public_pem: &[u8]) -> Result<Self> {
        let encoding = EncodingKey::from_ed_pem(private_pem)
            .map_err(|e| AuthError::Internal(format!("invalid private key: {e}")))?;
        let decoding = DecodingKey::from_ed_pem(public_pem)
            .map_err(|e| AuthError::Internal(format!("invalid public key: {e}")))?;
        Ok(Self { encoding, decoding })
    }

    #[instrument(skip(self, extra))]
    pub fn sign(
        &self,
        subject: Uuid,
        ttl_seconds: i64,
        extra: serde_json::Value,
    ) -> Result<String> {
        let now = Utc::now().timestamp();
        let claims = Claims {
            sub: subject.to_string(),
            exp: now + ttl_seconds,
            iat: now,
            jti: Uuid::new_v4().to_string(),
            org: None,
            extra,
        };
        let token = encode(&Header::new(Algorithm::EdDSA), &claims, &self.encoding)
            .map_err(|e| AuthError::Internal(format!("jwt sign failed: {e}")))?;

        tracing::debug!(sub = %subject, "jwt signed");
        Ok(token)
    }

    #[instrument(skip(self, token))]
    pub fn verify(&self, token: &str) -> Result<Claims> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.validate_exp = true;

        let data = decode::<Claims>(token, &self.decoding, &validation)
            .map_err(|_| AuthError::InvalidToken)?;

        tracing::debug!(sub = %data.claims.sub, "jwt verified");
        Ok(data.claims)
    }
}
