use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use chrono::Utc;
use tracing::instrument;
use uuid::Uuid;

use authx_core::{
    crypto::sha256_hex,
    error::{AuthError, Result},
    events::{AuthEvent, EventBus},
    models::{CreateCredential, CreateSession, CreateUser, CredentialKind, Session, User},
};
use authx_storage::ports::{CredentialRepository, SessionRepository, UserRepository};

#[derive(Debug)]
pub struct UsernameAuthResponse {
    pub user:    User,
    pub session: Session,
    pub token:   String,
}

/// Username + password authentication service.
///
/// Analogous to `EmailPasswordService` but lookups are by username instead of email.
pub struct UsernameService<S> {
    storage:          S,
    events:           EventBus,
    session_ttl_secs: i64,
    argon2:           Argon2<'static>,
}

impl<S> UsernameService<S>
where
    S: UserRepository + CredentialRepository + SessionRepository + Clone + Send + Sync + 'static,
{
    pub fn new(storage: S, events: EventBus, session_ttl_secs: i64) -> Self {
        use argon2::{Algorithm, Params, Version};
        let params = Params::new(65536, 3, 4, None).expect("valid argon2 params");
        Self {
            storage,
            events,
            session_ttl_secs,
            argon2: Argon2::new(Algorithm::Argon2id, Version::V0x13, params),
        }
    }

    /// Create a new account with a username + password.
    #[instrument(skip(self, password), fields(username = %username))]
    pub async fn sign_up(&self, username: &str, email: &str, password: &str) -> Result<User> {
        if password.len() < 8 {
            return Err(AuthError::WeakPassword);
        }
        let salt = SaltString::generate(&mut OsRng);
        let hash = self
            .argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::Internal(format!("argon2 hash: {e}")))?
            .to_string();

        let user = UserRepository::create(
            &self.storage,
            CreateUser {
                email:    email.to_owned(),
                username: Some(username.to_owned()),
                metadata: None,
            },
        )
        .await?;

        CredentialRepository::create(
            &self.storage,
            CreateCredential {
                user_id:         user.id,
                kind:            CredentialKind::Password,
                credential_hash: hash,
                metadata:        None,
            },
        )
        .await?;

        self.events.emit(AuthEvent::UserCreated { user: user.clone() });
        tracing::info!(user_id = %user.id, username = %username, "username sign-up complete");
        Ok(user)
    }

    /// Sign in with username + password, creating a new session on success.
    #[instrument(skip(self, password), fields(username = %username, ip = %ip))]
    pub async fn sign_in(&self, username: &str, password: &str, ip: &str) -> Result<UsernameAuthResponse> {
        let user = UserRepository::find_by_username(&self.storage, username)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;

        let hash_str = CredentialRepository::find_password_hash(&self.storage, user.id)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;

        let parsed = PasswordHash::new(&hash_str)
            .map_err(|e| AuthError::Internal(format!("argon2 parse: {e}")))?;
        if self.argon2.verify_password(password.as_bytes(), &parsed).is_err() {
            tracing::warn!(username = %username, "username sign-in: wrong password");
            return Err(AuthError::InvalidCredentials);
        }

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
        tracing::info!(user_id = %user.id, "username sign-in complete");
        Ok(UsernameAuthResponse { user, session, token: raw_str })
    }
}
