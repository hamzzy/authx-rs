use chrono::Utc;
use rand::Rng;
use tracing::instrument;
use uuid::Uuid;

use authx_core::{
    crypto::{hash_password, sha256_hex, verify_password},
    error::{AuthError, Result},
    events::{AuthEvent, EventBus},
    models::{CreateSession, CreateUser, Session, User},
};
use authx_storage::ports::{SessionRepository, UserRepository};

pub struct SignUpRequest {
    pub email:    String,
    pub password: String,
}

pub struct SignInRequest {
    pub email:    String,
    pub password: String,
    pub ip:       String,
}

pub struct AuthResponse {
    pub user:    User,
    pub session: Session,
    pub token:   String,
}

pub struct EmailPasswordService<S> {
    storage:          S,
    events:           EventBus,
    min_password_len: usize,
    session_ttl_secs: i64,
}

impl<S> EmailPasswordService<S>
where
    S: UserRepository + SessionRepository + Clone + Send + Sync + 'static,
{
    pub fn new(storage: S, events: EventBus, min_password_len: usize, session_ttl_secs: i64) -> Self {
        Self { storage, events, min_password_len, session_ttl_secs }
    }

    /// Register a new user with email + password.
    ///
    /// Returns the created [`User`]. The caller is responsible for persisting
    /// the password hash via the credential store (Phase 2 wires this fully).
    #[instrument(skip(self, req), fields(email = %req.email))]
    pub async fn sign_up(&self, req: SignUpRequest) -> Result<(User, String)> {
        if req.password.len() < self.min_password_len {
            return Err(AuthError::Internal(format!(
                "password must be at least {} characters",
                self.min_password_len
            )));
        }

        if UserRepository::find_by_email(&self.storage, &req.email).await?.is_some() {
            return Err(AuthError::EmailTaken);
        }

        let hash = hash_password(&req.password)?;

        let user = UserRepository::create(
            &self.storage,
            CreateUser { email: req.email, metadata: None },
        )
        .await?;

        self.events.emit(AuthEvent::UserCreated { user: user.clone() });
        tracing::info!(user_id = %user.id, "user created");
        Ok((user, hash))
    }

    /// Sign in with email + password.
    ///
    /// `password_hash` is the stored Argon2id hash for this user's credential.
    #[instrument(skip(self, req, password_hash), fields(email = %req.email))]
    pub async fn sign_in(&self, req: SignInRequest, password_hash: &str) -> Result<AuthResponse> {
        let user = UserRepository::find_by_email(&self.storage, &req.email)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;

        if !verify_password(password_hash, &req.password)? {
            tracing::warn!(email = %req.email, "wrong password");
            return Err(AuthError::InvalidCredentials);
        }

        let raw_token  = generate_token();
        let token_hash = sha256_hex(raw_token.as_bytes());

        let session = SessionRepository::create(
            &self.storage,
            CreateSession {
                user_id:     user.id,
                token_hash,
                device_info: serde_json::Value::Null,
                ip_address:  req.ip,
                org_id:      None,
                expires_at:  Utc::now() + chrono::Duration::seconds(self.session_ttl_secs),
            },
        )
        .await?;

        self.events.emit(AuthEvent::SignIn { user: user.clone(), session: session.clone() });
        tracing::info!(user_id = %user.id, session_id = %session.id, "sign in");

        Ok(AuthResponse { user, session, token: raw_token })
    }

    #[instrument(skip(self))]
    pub async fn sign_out(&self, session_id: Uuid) -> Result<()> {
        SessionRepository::invalidate(&self.storage, session_id).await?;
        tracing::info!(session_id = %session_id, "session invalidated");
        Ok(())
    }
}

fn generate_token() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(bytes)
}
