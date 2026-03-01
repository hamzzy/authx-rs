use std::sync::Arc;

use rand::Rng;
use totp_rs::{Algorithm, Secret, TOTP};
use tracing::instrument;
use uuid::Uuid;

use authx_core::{
    crypto::sha256_hex,
    error::{AuthError, Result},
    models::{CreateCredential, CredentialKind},
};
use authx_storage::ports::{CredentialRepository, UserRepository};

/// TOTP service — handles setup, verification, and backup codes.
///
/// Secrets are stored as `CredentialKind::Passkey` entries (reusing the
/// credential row with kind `"passkey"` to avoid schema changes).
/// The secret is stored as a base32-encoded string in `credential_hash`.
///
/// Backup codes are SHA-256 hashed and stored in metadata as a JSON array.
pub struct TotpService<S> {
    storage:  S,
    app_name: Arc<str>,
}

/// Returned when the user first enables TOTP.
#[derive(Debug)]
pub struct TotpSetup {
    /// Base32-encoded secret — store server-side and show once to user.
    pub secret_base32: String,
    /// `otpauth://totp/...` URI for QR code generation.
    pub otpauth_uri:   String,
    /// One-time backup codes (show to user, hash before storing).
    pub backup_codes:  Vec<String>,
}

pub struct TotpVerifyRequest {
    pub user_id: Uuid,
    pub code:    String,
}

impl<S> TotpService<S>
where
    S: UserRepository + CredentialRepository + Clone + Send + Sync + 'static,
{
    pub fn new(storage: S, app_name: impl Into<Arc<str>>) -> Self {
        Self { storage, app_name: app_name.into() }
    }

    /// Generate a new TOTP secret and backup codes for a user.
    /// Call `confirm_setup` with the first code before persisting.
    #[instrument(skip(self), fields(user_id = %user_id))]
    pub async fn begin_setup(&self, user_id: Uuid) -> Result<TotpSetup> {
        let user = UserRepository::find_by_id(&self.storage, user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let secret = Secret::generate_secret();
        let secret_base32 = secret.to_encoded().to_string();

        let totp = build_totp(&secret_base32, &user.email, &self.app_name)?;
        let otpauth_uri = totp.get_url();

        let backup_codes = generate_backup_codes(8);

        tracing::info!(user_id = %user_id, "totp setup initiated");
        Ok(TotpSetup { secret_base32, otpauth_uri, backup_codes })
    }

    /// Confirm the user can produce a valid code, then persist the secret.
    #[instrument(skip(self, setup, code), fields(user_id = %user_id))]
    pub async fn confirm_setup(
        &self,
        user_id: Uuid,
        setup:   &TotpSetup,
        code:    &str,
    ) -> Result<()> {
        let user = UserRepository::find_by_id(&self.storage, user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let totp = build_totp(&setup.secret_base32, &user.email, &self.app_name)?;
        if !totp.check_current(code).map_err(|_| AuthError::InvalidToken)? {
            return Err(AuthError::InvalidToken);
        }

        let hashed_codes: Vec<String> = setup
            .backup_codes
            .iter()
            .map(|c| sha256_hex(c.as_bytes()))
            .collect();

        CredentialRepository::create(
            &self.storage,
            CreateCredential {
                user_id,
                kind:            CredentialKind::Passkey,
                credential_hash: setup.secret_base32.clone(),
                metadata:        Some(serde_json::json!({ "backup_codes": hashed_codes })),
            },
        )
        .await?;

        tracing::info!(user_id = %user_id, "totp enabled");
        Ok(())
    }

    /// Verify a TOTP code (or a backup code) during sign-in.
    #[instrument(skip(self, req), fields(user_id = %req.user_id))]
    pub async fn verify(&self, req: TotpVerifyRequest) -> Result<()> {
        let user = UserRepository::find_by_id(&self.storage, req.user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let cred = CredentialRepository::find_by_user_and_kind(
            &self.storage,
            req.user_id,
            CredentialKind::Passkey,
        )
        .await?
        .ok_or(AuthError::InvalidToken)?;

        let totp = build_totp(&cred.credential_hash, &user.email, &self.app_name)?;
        if totp.check_current(&req.code).map_err(|_| AuthError::InvalidToken)? {
            tracing::info!(user_id = %req.user_id, "totp verified");
            return Ok(());
        }

        // Try backup codes (single-use; a full impl would update the DB row).
        let code_hash = sha256_hex(req.code.as_bytes());
        let codes: Vec<String> = cred
            .metadata
            .get("backup_codes")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        if codes.contains(&code_hash) {
            tracing::info!(user_id = %req.user_id, "totp: backup code accepted");
            return Ok(());
        }

        tracing::warn!(user_id = %req.user_id, "totp verification failed");
        Err(AuthError::InvalidToken)
    }

    /// Remove TOTP from a user account.
    #[instrument(skip(self), fields(user_id = %user_id))]
    pub async fn disable(&self, user_id: Uuid) -> Result<()> {
        CredentialRepository::delete_by_user_and_kind(
            &self.storage,
            user_id,
            CredentialKind::Passkey,
        )
        .await?;
        tracing::info!(user_id = %user_id, "totp disabled");
        Ok(())
    }

    /// Returns `true` if the user has TOTP enabled.
    pub async fn is_enabled(&self, user_id: Uuid) -> Result<bool> {
        Ok(CredentialRepository::find_by_user_and_kind(
            &self.storage,
            user_id,
            CredentialKind::Passkey,
        )
        .await?
        .is_some())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn build_totp(secret_base32: &str, email: &str, app_name: &str) -> Result<TOTP> {
    let secret = Secret::Encoded(secret_base32.to_owned());
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().map_err(|_| AuthError::InvalidToken)?,
        Some(app_name.to_owned()),
        email.to_owned(),
    )
    .map_err(|e| AuthError::Internal(format!("totp init: {e}")))
}

fn generate_backup_codes(count: usize) -> Vec<String> {
    let mut rng = rand::thread_rng();
    (0..count)
        .map(|_| {
            (0..8)
                .map(|_| {
                    let idx = rng.gen_range(0..36u8);
                    (if idx < 10 { b'0' + idx } else { b'A' + idx - 10 }) as char
                })
                .collect::<String>()
        })
        .collect()
}
