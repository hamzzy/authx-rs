use std::time::Duration;

use chrono::Utc;
use tracing::instrument;

use authx_core::{
    crypto::sha256_hex,
    error::{AuthError, Result},
    events::{AuthEvent, EventBus},
    models::{CreateSession, Session, User},
};
use authx_storage::ports::{SessionRepository, UserRepository};

use crate::one_time_token::{OneTimeTokenStore, TokenKind};

/// Returned when a magic link is successfully verified.
#[derive(Debug)]
pub struct MagicLinkVerifyResponse {
    pub user:    User,
    pub session: Session,
    /// Raw session token — send to client once; store SHA-256 hash server-side.
    pub token:   String,
}

/// Magic link authentication service.
///
/// # Flow
/// 1. App calls `request_link(email)` → gets a raw token (send in email yourself).
/// 2. User clicks link → app calls `verify(token, ip)` → session is created.
///
/// The magic link token is single-use and expires after `ttl` (default 15 min).
pub struct MagicLinkService<S> {
    storage:         S,
    events:          EventBus,
    token_store:     OneTimeTokenStore,
    session_ttl_secs: i64,
}

impl<S> MagicLinkService<S>
where
    S: UserRepository + SessionRepository + Clone + Send + Sync + 'static,
{
    pub fn new(storage: S, events: EventBus, session_ttl_secs: i64) -> Self {
        Self {
            storage,
            events,
            token_store:     OneTimeTokenStore::new(Duration::from_secs(15 * 60)),
            session_ttl_secs,
        }
    }

    pub fn with_link_ttl(mut self, ttl: Duration) -> Self {
        self.token_store = OneTimeTokenStore::new(ttl);
        self
    }

    /// Issue a magic link token for the given email.
    ///
    /// Returns `None` for unknown emails (to avoid user enumeration).
    #[instrument(skip(self), fields(email = %email))]
    pub async fn request_link(&self, email: &str) -> Result<Option<String>> {
        let user = match UserRepository::find_by_email(&self.storage, email).await? {
            Some(u) => u,
            None    => {
                tracing::debug!("magic link requested for unknown email");
                return Ok(None);
            }
        };

        let token = self.token_store.issue(user.id, TokenKind::MagicLink);
        tracing::info!(user_id = %user.id, "magic link token issued");
        Ok(Some(token))
    }

    /// Consume the token, create a session, and return auth credentials.
    #[instrument(skip(self, raw_token), fields(ip = %ip))]
    pub async fn verify(&self, raw_token: &str, ip: &str) -> Result<MagicLinkVerifyResponse> {
        let user_id = self
            .token_store
            .consume(raw_token, TokenKind::MagicLink)
            .ok_or(AuthError::InvalidToken)?;

        let user = UserRepository::find_by_id(&self.storage, user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        // Generate session token.
        let raw_session_token: [u8; 32] = rand::thread_rng().gen();
        let raw_session_str   = hex::encode(raw_session_token);
        let token_hash        = sha256_hex(raw_session_str.as_bytes());

        let session = SessionRepository::create(
            &self.storage,
            CreateSession {
                user_id:     user.id,
                token_hash,
                device_info: serde_json::Value::Null,
                ip_address:  ip.to_owned(),
                org_id:      None,
                expires_at:  Utc::now() + chrono::Duration::seconds(self.session_ttl_secs),
            },
        )
        .await?;

        self.events.emit(AuthEvent::SignIn { user: user.clone(), session: session.clone() });
        tracing::info!(user_id = %user_id, session_id = %session.id, "magic link sign-in complete");

        Ok(MagicLinkVerifyResponse { user, session, token: raw_session_str })
    }
}

// pull in rand/hex for the session token generation
use rand::Rng;
