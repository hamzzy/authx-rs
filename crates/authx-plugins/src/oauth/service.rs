use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use rand::Rng;
use sha2::{Digest, Sha256};
use tracing::instrument;

use authx_core::{
    crypto::{encrypt, sha256_hex},
    error::{AuthError, Result},
    events::{AuthEvent, EventBus},
    models::{CreateSession, CreateUser, Session, UpsertOAuthAccount, User},
};
use authx_storage::ports::{OAuthAccountRepository, SessionRepository, UserRepository};

use super::providers::OAuthProvider;

/// Returned from `begin()`. The caller should store `state` and `code_verifier`
/// (e.g., in a server-side session or signed cookie) to verify the callback.
#[derive(Debug)]
pub struct OAuthBeginResponse {
    pub authorization_url: String,
    pub state:             String,
    pub code_verifier:     String,
}

/// OAuth authentication service supporting multiple providers.
///
/// Providers are registered by name via [`OAuthService::register`].
pub struct OAuthService<S> {
    storage:          S,
    events:           EventBus,
    providers:        std::collections::HashMap<String, Arc<dyn OAuthProvider>>,
    session_ttl_secs: i64,
    /// 32-byte key for AES-256-GCM token encryption.
    encryption_key:   [u8; 32],
}

impl<S> OAuthService<S>
where
    S: UserRepository + SessionRepository + OAuthAccountRepository + Clone + Send + Sync + 'static,
{
    pub fn new(
        storage:          S,
        events:           EventBus,
        session_ttl_secs: i64,
        encryption_key:   [u8; 32],
    ) -> Self {
        Self {
            storage,
            events,
            providers:        Default::default(),
            session_ttl_secs,
            encryption_key,
        }
    }

    /// Register an OAuth provider.
    pub fn register(mut self, provider: impl OAuthProvider + 'static) -> Self {
        self.providers.insert(provider.name().to_owned(), Arc::new(provider));
        self
    }

    fn provider(&self, name: &str) -> Result<&dyn OAuthProvider> {
        self.providers
            .get(name)
            .map(|p| p.as_ref())
            .ok_or_else(|| AuthError::Internal(format!("unknown oauth provider: {name}")))
    }

    /// Begin an OAuth flow. Generate PKCE verifier+challenge and a random state.
    #[instrument(skip(self), fields(provider = %provider_name))]
    pub fn begin(&self, provider_name: &str, _redirect_uri: &str) -> Result<OAuthBeginResponse> {
        self.provider(provider_name)?;

        // Generate PKCE code_verifier (32 random bytes, base64url-encoded).
        let verifier_bytes: [u8; 32] = rand::thread_rng().gen();
        let code_verifier  = URL_SAFE_NO_PAD.encode(verifier_bytes);

        // code_challenge = BASE64URL(SHA256(verifier))
        let mut hasher = Sha256::new();
        hasher.update(code_verifier.as_bytes());
        let digest = hasher.finalize();
        let code_challenge = URL_SAFE_NO_PAD.encode(digest);

        // Random state token.
        let state_bytes: [u8; 16] = rand::thread_rng().gen();
        let state = hex::encode(state_bytes);

        let authorization_url = self.provider(provider_name)?.authorization_url(&state, &code_challenge);

        tracing::info!(provider = %provider_name, "oauth flow started");
        Ok(OAuthBeginResponse { authorization_url, state, code_verifier })
    }

    /// Handle the OAuth callback. Exchange the code, fetch user info, upsert the
    /// OAuth account, find-or-create the user by email, and create a session.
    #[instrument(skip(self, code, code_verifier), fields(provider = %provider_name, ip = %ip))]
    pub async fn callback(
        &self,
        provider_name: &str,
        code:          &str,
        _state:        &str,
        code_verifier: &str,
        redirect_uri:  &str,
        ip:            &str,
    ) -> Result<(User, Session, String)> {
        let provider = self.provider(provider_name)?;
        let tokens   = provider.exchange_code(code, code_verifier, redirect_uri).await?;
        let info     = provider.fetch_user_info(&tokens.access_token).await?;

        // Encrypt tokens before storing.
        let access_enc  = encrypt(&self.encryption_key, tokens.access_token.as_bytes())
            .map_err(|e| AuthError::Internal(format!("token encrypt: {e}")))?;
        let refresh_enc = tokens.refresh_token.as_deref()
            .map(|r| encrypt(&self.encryption_key, r.as_bytes()))
            .transpose()
            .map_err(|e| AuthError::Internal(format!("token encrypt: {e}")))?;

        let expires_at = tokens.expires_in
            .map(|secs| Utc::now() + chrono::Duration::seconds(secs as i64));

        // Find or create user by email.
        let user = match UserRepository::find_by_email(&self.storage, &info.email).await? {
            Some(u) => u,
            None    => {
                let u = UserRepository::create(
                    &self.storage,
                    CreateUser {
                        email:    info.email.clone(),
                        username: None,
                        metadata: None,
                    },
                )
                .await?;
                self.events.emit(AuthEvent::UserCreated { user: u.clone() });
                u
            }
        };

        // Upsert OAuth account.
        OAuthAccountRepository::upsert(
            &self.storage,
            UpsertOAuthAccount {
                user_id:           user.id,
                provider:          provider_name.to_owned(),
                provider_user_id:  info.provider_user_id,
                access_token_enc:  access_enc,
                refresh_token_enc: refresh_enc,
                expires_at,
            },
        )
        .await?;

        self.events.emit(AuthEvent::OAuthLinked {
            user_id:  user.id,
            provider: provider_name.to_owned(),
        });

        // Create session.
        let raw: [u8; 32] = rand::thread_rng().gen();
        let raw_str    = hex::encode(raw);
        let token_hash = sha256_hex(raw_str.as_bytes());

        let session = SessionRepository::create(
            &self.storage,
            CreateSession {
                user_id:     user.id,
                token_hash,
                device_info: serde_json::json!({ "provider": provider_name }),
                ip_address:  ip.to_owned(),
                org_id:      None,
                expires_at:  Utc::now() + chrono::Duration::seconds(self.session_ttl_secs),
            },
        )
        .await?;

        self.events.emit(AuthEvent::SignIn { user: user.clone(), session: session.clone() });
        tracing::info!(user_id = %user.id, provider = %provider_name, "oauth sign-in complete");
        Ok((user, session, raw_str))
    }
}
