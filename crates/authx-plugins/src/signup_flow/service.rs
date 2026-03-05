use tracing::instrument;

use authx_core::{error::Result, events::EventBus, models::User};
use authx_storage::ports::{CredentialRepository, SessionRepository, UserRepository};

use crate::{
    email_password::{EmailPasswordService, SignUpRequest},
    email_verification::EmailVerificationService,
    totp::TotpService,
};

pub struct SignupFlowRequest {
    pub email: String,
    pub password: String,
    pub ip: String,
    /// If true, generate TOTP setup material immediately after sign-up.
    pub setup_mfa: bool,
}

pub struct SignupFlowResponse {
    pub user: User,
    pub email_verification_token: String,
    pub totp_setup: Option<crate::totp::TotpSetup>,
}

/// Orchestrated sign-up flow:
/// 1. Create user + password credential
/// 2. Issue email verification token
/// 3. Optionally bootstrap MFA (TOTP)
pub struct SignupFlowService<S> {
    email_password: EmailPasswordService<S>,
    email_verification: EmailVerificationService<S>,
    totp: TotpService<S>,
}

impl<S> SignupFlowService<S>
where
    S: UserRepository + SessionRepository + CredentialRepository + Clone + Send + Sync + 'static,
{
    pub fn new(
        storage: S,
        events: EventBus,
        min_password_len: usize,
        session_ttl_secs: i64,
        totp_app_name: impl Into<std::sync::Arc<str>>,
    ) -> Self {
        Self {
            email_password: EmailPasswordService::new(
                storage.clone(),
                events.clone(),
                min_password_len,
                session_ttl_secs,
            ),
            email_verification: EmailVerificationService::new(storage.clone(), events),
            totp: TotpService::new(storage, totp_app_name),
        }
    }

    #[instrument(skip(self, req), fields(email = %req.email, setup_mfa = req.setup_mfa))]
    pub async fn sign_up(&self, req: SignupFlowRequest) -> Result<SignupFlowResponse> {
        let user = self
            .email_password
            .sign_up(SignUpRequest {
                email: req.email,
                password: req.password,
                ip: req.ip,
            })
            .await?;

        let email_verification_token = self.email_verification.issue(user.id).await?;
        let totp_setup = if req.setup_mfa {
            Some(self.totp.begin_setup(user.id).await?)
        } else {
            None
        };

        Ok(SignupFlowResponse {
            user,
            email_verification_token,
            totp_setup,
        })
    }
}
