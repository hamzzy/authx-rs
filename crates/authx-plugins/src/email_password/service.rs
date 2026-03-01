use chrono::Utc;
use rand::Rng;
use tracing::instrument;
use uuid::Uuid;

use authx_core::{
    crypto::{hash_password, sha256_hex, verify_password},
    error::{AuthError, Result},
    events::{AuthEvent, EventBus},
    models::{CreateCredential, CreateSession, CreateUser, CredentialKind, Session, User},
};
use authx_storage::ports::{CredentialRepository, SessionRepository, UserRepository};

pub struct SignUpRequest {
    pub email:    String,
    pub password: String,
    pub ip:       String,
}

pub struct SignInRequest {
    pub email:    String,
    pub password: String,
    pub ip:       String,
}

#[derive(Debug)]
pub struct AuthResponse {
    pub user:    User,
    pub session: Session,
    /// Raw opaque token returned to the client once. The SHA-256 hash is
    /// stored in the database — never the raw value.
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
    S: UserRepository + SessionRepository + CredentialRepository + Clone + Send + Sync + 'static,
{
    pub fn new(storage: S, events: EventBus, min_password_len: usize, session_ttl_secs: i64) -> Self {
        Self { storage, events, min_password_len, session_ttl_secs }
    }

    #[instrument(skip(self, req), fields(email = %req.email))]
    pub async fn sign_up(&self, req: SignUpRequest) -> Result<User> {
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
        tracing::info!(user_id = %user.id, "user registered");
        Ok(user)
    }

    #[instrument(skip(self, req), fields(email = %req.email))]
    pub async fn sign_in(&self, req: SignInRequest) -> Result<AuthResponse> {
        let user = UserRepository::find_by_email(&self.storage, &req.email)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;

        let hash = CredentialRepository::find_password_hash(&self.storage, user.id)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;

        if !verify_password(&hash, &req.password)? {
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
        tracing::info!(user_id = %user.id, session_id = %session.id, "signed in");

        Ok(AuthResponse { user, session, token: raw_token })
    }

    #[instrument(skip(self))]
    pub async fn sign_out(&self, session_id: Uuid) -> Result<()> {
        SessionRepository::invalidate(&self.storage, session_id).await?;
        tracing::info!(session_id = %session_id, "session invalidated");
        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn sign_out_all(&self, user_id: Uuid) -> Result<()> {
        SessionRepository::invalidate_all_for_user(&self.storage, user_id).await?;
        tracing::info!(user_id = %user_id, "all sessions invalidated");
        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn list_sessions(&self, user_id: Uuid) -> Result<Vec<Session>> {
        SessionRepository::find_by_user(&self.storage, user_id).await
    }
}

fn generate_token() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(bytes)
}
