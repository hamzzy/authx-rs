use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use tracing::instrument;
use uuid::Uuid;

use authx_core::{
    crypto::sha256_hex,
    error::{AuthError, Result},
    models::{ApiKey, CreateApiKey},
};
use authx_storage::ports::{ApiKeyRepository, UserRepository};

/// Maximum lifetime for an API key.
const MAX_KEY_TTL: Duration = Duration::days(365);

/// Returned when an API key is first created — the `raw_key` is shown once only.
#[derive(Debug)]
pub struct ApiKeyResponse {
    pub key: ApiKey,
    pub raw_key: String,
}

pub struct ApiKeyService<S> {
    storage: S,
}

impl<S> ApiKeyService<S>
where
    S: UserRepository + ApiKeyRepository + Clone + Send + Sync + 'static,
{
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Create a new API key for `user_id`. Returns the `ApiKey` row and the
    /// raw key (hex-encoded 32 random bytes). The raw key is **never stored**;
    /// only the SHA-256 hash is persisted.
    ///
    /// `expires_at` is required and must be at most [`MAX_KEY_TTL`] (365 days) in the future.
    #[instrument(skip(self), fields(user_id = %user_id))]
    pub async fn create(
        &self,
        user_id: Uuid,
        org_id: Option<Uuid>,
        name: String,
        scopes: Vec<String>,
        expires_at: DateTime<Utc>,
    ) -> Result<ApiKeyResponse> {
        let now = Utc::now();
        if expires_at <= now {
            return Err(AuthError::Internal(
                "api key expiry must be in the future".into(),
            ));
        }
        let max_expiry = now + MAX_KEY_TTL;
        if expires_at > max_expiry {
            return Err(AuthError::Internal(format!(
                "api key expiry exceeds maximum allowed ({} days)",
                MAX_KEY_TTL.num_days()
            )));
        }

        // Verify user exists.
        UserRepository::find_by_id(&self.storage, user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let raw: [u8; 32] = rand::thread_rng().gen();
        let raw_key = hex::encode(raw);
        let key_hash = sha256_hex(raw_key.as_bytes());
        let prefix = raw_key[..8].to_owned();

        let key = ApiKeyRepository::create(
            &self.storage,
            CreateApiKey {
                user_id,
                org_id,
                key_hash,
                prefix,
                name,
                scopes,
                expires_at: Some(expires_at),
            },
        )
        .await?;

        tracing::info!(user_id = %user_id, key_id = %key.id, "api key created");
        Ok(ApiKeyResponse { key, raw_key })
    }

    /// List all API keys belonging to `user_id`.
    #[instrument(skip(self), fields(user_id = %user_id))]
    pub async fn list(&self, user_id: Uuid) -> Result<Vec<ApiKey>> {
        let keys = ApiKeyRepository::find_by_user(&self.storage, user_id).await?;
        tracing::debug!(user_id = %user_id, count = keys.len(), "api keys listed");
        Ok(keys)
    }

    /// Revoke (delete) an API key. Enforces that the key belongs to `user_id`.
    #[instrument(skip(self), fields(user_id = %user_id, key_id = %key_id))]
    pub async fn revoke(&self, user_id: Uuid, key_id: Uuid) -> Result<()> {
        ApiKeyRepository::revoke(&self.storage, key_id, user_id).await?;
        tracing::info!(user_id = %user_id, key_id = %key_id, "api key revoked");
        Ok(())
    }

    /// Authenticate using a raw API key string.
    ///
    /// Returns `Err(AuthError::InvalidToken)` if the key is unknown, expired,
    /// or otherwise invalid. On success, updates `last_used_at`.
    #[instrument(skip(self, raw_key))]
    pub async fn authenticate(&self, raw_key: &str) -> Result<ApiKey> {
        let key_hash = sha256_hex(raw_key.as_bytes());
        let key = ApiKeyRepository::find_by_hash(&self.storage, &key_hash)
            .await?
            .ok_or(AuthError::InvalidToken)?;

        if let Some(exp) = key.expires_at {
            if exp < Utc::now() {
                tracing::warn!(key_id = %key.id, "api key expired");
                return Err(AuthError::InvalidToken);
            }
        }

        let now = Utc::now();
        ApiKeyRepository::touch_last_used(&self.storage, key.id, now).await?;
        tracing::info!(key_id = %key.id, user_id = %key.user_id, "api key authenticated");
        Ok(ApiKey {
            last_used_at: Some(now),
            ..key
        })
    }
}
