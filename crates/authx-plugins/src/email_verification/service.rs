use std::time::Duration;

use tracing::instrument;
use uuid::Uuid;

use authx_core::{
    error::{AuthError, Result},
    events::{AuthEvent, EventBus},
    models::UpdateUser,
};
use authx_storage::ports::UserRepository;

use crate::one_time_token::{OneTimeTokenStore, TokenKind};

/// Issues and verifies email verification tokens.
///
/// # Flow
/// 1. Call `issue(user_id)` → send the returned token in an email link.
/// 2. User clicks link → call `verify(token)` → sets `email_verified = true`.
pub struct EmailVerificationService<S> {
    storage: S,
    events: EventBus,
    token_store: OneTimeTokenStore,
}

impl<S> EmailVerificationService<S>
where
    S: UserRepository + Clone + Send + Sync + 'static,
{
    pub fn new(storage: S, events: EventBus) -> Self {
        Self {
            storage,
            events,
            token_store: OneTimeTokenStore::new(Duration::from_secs(24 * 60 * 60)),
        }
    }

    /// Issue a 24-hour verification token for the given user.
    #[instrument(skip(self), fields(user_id = %user_id))]
    pub async fn issue(&self, user_id: Uuid) -> Result<String> {
        UserRepository::find_by_id(&self.storage, user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let token = self
            .token_store
            .issue(user_id, TokenKind::EmailVerification);
        tracing::info!(user_id = %user_id, "email verification token issued");
        Ok(token)
    }

    /// Consume the token and mark the user's email as verified.
    #[instrument(skip(self, raw_token))]
    pub async fn verify(&self, raw_token: &str) -> Result<()> {
        let user_id = self
            .token_store
            .consume(raw_token, TokenKind::EmailVerification)
            .ok_or(AuthError::InvalidToken)?;

        UserRepository::update(
            &self.storage,
            user_id,
            UpdateUser {
                email_verified: Some(true),
                ..Default::default()
            },
        )
        .await?;

        self.events.emit(AuthEvent::EmailVerified { user_id });
        tracing::info!(user_id = %user_id, "email verified");
        Ok(())
    }
}
