use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use chrono::Utc;
use tracing::instrument;
use uuid::Uuid;

use authx_core::{
    crypto::sha256_hex,
    error::{AuthError, Result},
    events::{AuthEvent, EventBus},
    models::{CreateCredential, CreateSession, CreateUser, CredentialKind, Session, UpdateUser, User},
};
use authx_storage::ports::{CredentialRepository, SessionRepository, UserRepository};

/// The guest auth credentials returned from `create_guest`.
#[derive(Debug)]
pub struct GuestSession {
    pub user:    User,
    pub session: Session,
    /// Raw session token — show to client once.
    pub token:   String,
}

/// Anonymous / guest authentication service.
///
/// Guest accounts are real `User` rows with a synthetic email and
/// `metadata: {"guest": true}`. They can be upgraded later.
pub struct AnonymousService<S> {
    storage:          S,
    events:           EventBus,
    session_ttl_secs: i64,
    argon2:           Argon2<'static>,
}

impl<S> AnonymousService<S>
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

    /// Create an anonymous guest session. The returned `User` row has a synthetic
    /// `guest_<uuid>@authx.guest` email and `metadata: {"guest": true}`.
    #[instrument(skip(self), fields(ip = %ip))]
    pub async fn create_guest(&self, ip: &str) -> Result<GuestSession> {
        let guest_id = Uuid::new_v4();
        let email    = format!("guest_{}@authx.guest", guest_id);

        let user = UserRepository::create(
            &self.storage,
            CreateUser {
                email:    email.clone(),
                username: None,
                metadata: Some(serde_json::json!({ "guest": true })),
            },
        )
        .await?;

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

        self.events.emit(AuthEvent::UserCreated { user: user.clone() });
        self.events.emit(AuthEvent::SignIn { user: user.clone(), session: session.clone() });
        tracing::info!(user_id = %user.id, "guest session created");
        Ok(GuestSession { user, session, token: raw_str })
    }

    /// Upgrade a guest account to a real account by setting a real email + password.
    ///
    /// The user row is updated in-place; the guest session remains valid.
    #[instrument(skip(self, password), fields(guest_user_id = %guest_user_id))]
    pub async fn upgrade(
        &self,
        guest_user_id: Uuid,
        email:         &str,
        password:      &str,
    ) -> Result<User> {
        let user = UserRepository::find_by_id(&self.storage, guest_user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        // Only upgrade actual guest accounts.
        let is_guest = user
            .metadata
            .get("guest")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !is_guest {
            return Err(AuthError::Forbidden);
        }

        if password.len() < 8 {
            return Err(AuthError::WeakPassword);
        }
        let salt = SaltString::generate(&mut OsRng);
        let hash = self
            .argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::Internal(format!("argon2 hash: {e}")))?
            .to_string();

        let updated = UserRepository::update(
            &self.storage,
            guest_user_id,
            UpdateUser {
                email:    Some(email.to_owned()),
                metadata: Some(serde_json::json!({ "guest": false })),
                ..Default::default()
            },
        )
        .await?;

        CredentialRepository::create(
            &self.storage,
            CreateCredential {
                user_id:         guest_user_id,
                kind:            CredentialKind::Password,
                credential_hash: hash,
                metadata:        None,
            },
        )
        .await?;

        self.events.emit(AuthEvent::UserUpdated { user: updated.clone() });
        tracing::info!(user_id = %guest_user_id, email = %email, "guest account upgraded");
        Ok(updated)
    }
}
