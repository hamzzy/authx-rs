use std::time::Duration;

use tracing::instrument;

use authx_core::{
    crypto::{hash_password, verify_password},
    error::{AuthError, Result},
    events::{AuthEvent, EventBus},
    models::{CreateCredential, CredentialKind},
};
use authx_storage::ports::{CredentialRepository, UserRepository};

use crate::one_time_token::{OneTimeTokenStore, TokenKind};

pub struct PasswordResetRequest {
    /// Token received from the reset link.
    pub token: String,
    /// The new password the user wants to set.
    pub new_password: String,
}

/// Password reset service.
///
/// # Flow
/// 1. App calls `request_reset(email)` → gets a raw token (send it in the
///    reset email yourself — authx does not send email).
/// 2. User clicks link → app calls `reset_password(token, new_password)`.
///
/// Tokens expire after `ttl` (default 30 minutes) and are single-use.
pub struct PasswordResetService<S> {
    storage: S,
    events: EventBus,
    token_store: OneTimeTokenStore,
    min_pass_len: usize,
}

impl<S> PasswordResetService<S>
where
    S: UserRepository + CredentialRepository + Clone + Send + Sync + 'static,
{
    pub fn new(storage: S, events: EventBus) -> Self {
        Self {
            storage,
            events,
            token_store: OneTimeTokenStore::new(Duration::from_secs(30 * 60)),
            min_pass_len: 8,
        }
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.token_store = OneTimeTokenStore::new(ttl);
        self
    }

    /// Issue a reset token for the given email.
    ///
    /// Always succeeds (even for unknown emails) to avoid user enumeration.
    /// Returns `None` if the email is not registered — caller should silently
    /// ignore and not reveal this to the client.
    #[instrument(skip(self), fields(email = %email))]
    pub async fn request_reset(&self, email: &str) -> Result<Option<String>> {
        let user = match UserRepository::find_by_email(&self.storage, email).await? {
            Some(u) => u,
            None => {
                tracing::debug!("password reset requested for unknown email");
                return Ok(None);
            }
        };

        let token = self.token_store.issue(user.id, TokenKind::PasswordReset);
        tracing::info!(user_id = %user.id, "password reset token issued");
        Ok(Some(token))
    }

    /// Consume the reset token and update the password.
    #[instrument(skip(self, req))]
    pub async fn reset_password(&self, req: PasswordResetRequest) -> Result<()> {
        if req.new_password.len() < self.min_pass_len {
            return Err(AuthError::Internal(format!(
                "password must be at least {} characters",
                self.min_pass_len
            )));
        }

        let user_id = self
            .token_store
            .consume(&req.token, TokenKind::PasswordReset)
            .ok_or(AuthError::InvalidToken)?;

        // Verify the new password isn't the same as the current one.
        if let Some(old_hash) =
            CredentialRepository::find_password_hash(&self.storage, user_id).await?
        {
            if verify_password(&old_hash, &req.new_password)? {
                return Err(AuthError::Internal(
                    "new password must differ from current".into(),
                ));
            }
            CredentialRepository::delete_by_user_and_kind(
                &self.storage,
                user_id,
                CredentialKind::Password,
            )
            .await?;
        }

        let new_hash = hash_password(&req.new_password)?;
        CredentialRepository::create(
            &self.storage,
            CreateCredential {
                user_id,
                kind: CredentialKind::Password,
                credential_hash: new_hash,
                metadata: None,
            },
        )
        .await?;

        self.events.emit(AuthEvent::PasswordChanged { user_id });
        tracing::info!(user_id = %user_id, "password reset complete");
        Ok(())
    }
}
