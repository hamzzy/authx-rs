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

#[derive(Debug)]
pub struct EmailOtpVerifyResponse {
    pub user:    User,
    pub session: Session,
    pub token:   String,
}

/// Email OTP authentication — issues a short-lived one-time code (token)
/// that the caller sends to the user's email address.
///
/// # Flow
/// 1. `issue(email)` → raw token (send in email). Returns `None` for unknown emails.
/// 2. `verify(raw_token, ip)` → session created, `EmailOtpVerifyResponse` returned.
pub struct EmailOtpService<S> {
    storage:          S,
    events:           EventBus,
    token_store:      OneTimeTokenStore,
    session_ttl_secs: i64,
}

impl<S> EmailOtpService<S>
where
    S: UserRepository + SessionRepository + Clone + Send + Sync + 'static,
{
    pub fn new(storage: S, events: EventBus, session_ttl_secs: i64) -> Self {
        Self {
            storage,
            events,
            token_store: OneTimeTokenStore::new(Duration::from_secs(10 * 60)),
            session_ttl_secs,
        }
    }

    /// Issue an OTP token for the given email. Returns `None` for unknown emails
    /// (avoids user enumeration).
    #[instrument(skip(self), fields(email = %email))]
    pub async fn issue(&self, email: &str) -> Result<Option<String>> {
        let user = match UserRepository::find_by_email(&self.storage, email).await? {
            Some(u) => u,
            None    => {
                tracing::debug!("email otp requested for unknown email");
                return Ok(None);
            }
        };
        let token = self.token_store.issue(user.id, TokenKind::EmailOtp);
        tracing::info!(user_id = %user.id, "email otp issued");
        Ok(Some(token))
    }

    /// Consume the OTP token and create an authenticated session.
    #[instrument(skip(self, raw_token), fields(ip = %ip))]
    pub async fn verify(&self, raw_token: &str, ip: &str) -> Result<EmailOtpVerifyResponse> {
        let user_id = self
            .token_store
            .consume(raw_token, TokenKind::EmailOtp)
            .ok_or(AuthError::InvalidToken)?;

        let user = UserRepository::find_by_id(&self.storage, user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let raw: [u8; 32] = rand::Rng::gen(&mut rand::thread_rng());
        let raw_str    = hex::encode(raw);
        let token_hash = sha256_hex(raw_str.as_bytes());

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
        tracing::info!(user_id = %user_id, session_id = %session.id, "email otp sign-in complete");
        Ok(EmailOtpVerifyResponse { user, session, token: raw_str })
    }
}
