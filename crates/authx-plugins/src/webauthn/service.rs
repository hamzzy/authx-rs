use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use chrono::Utc;
use rand::Rng;
use serde::Serialize;
use tracing::instrument;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url, Webauthn,
    WebauthnBuilder,
};

use authx_core::{
    crypto::sha256_hex,
    error::{AuthError, Result, StorageError},
    models::{CreateCredential, CreateSession, CredentialKind},
};
use authx_storage::ports::{CredentialRepository, SessionRepository, UserRepository};

enum PendingCeremony {
    Registration {
        user_id: Uuid,
        state: PasskeyRegistration,
        expires_at: Instant,
    },
    Authentication {
        user_id: Uuid,
        state: PasskeyAuthentication,
        passkey: Passkey,
        expires_at: Instant,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct WebAuthnBeginResponse {
    /// Opaque server-side ceremony id (previously challenge id in this API).
    pub challenge: String,
    pub user_id: Uuid,
    pub timeout_secs: u64,
    pub options: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct FinishRegistrationRequest {
    pub challenge: String,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebAuthnRegistrationResult {
    pub user_id: Uuid,
    pub credential_stored: bool,
}

#[derive(Debug, Clone)]
pub struct FinishAuthenticationRequest {
    pub challenge: String,
    pub credential: PublicKeyCredential,
    pub ip: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebAuthnAuthenticationResult {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub token: String,
}

/// WebAuthn/passkey service powered by `webauthn-rs`.
///
/// Registration/authentication states are held server-side in memory and
/// expire by TTL. Registered passkeys are persisted in credential metadata.
pub struct WebAuthnService<S> {
    storage: S,
    webauthn: Webauthn,
    challenge_ttl: Duration,
    session_ttl_secs: i64,
    pending: Arc<RwLock<HashMap<String, PendingCeremony>>>,
}

impl<S> WebAuthnService<S>
where
    S: UserRepository + CredentialRepository + SessionRepository + Clone + Send + Sync + 'static,
{
    pub fn new(
        storage: S,
        rp_id: impl Into<String>,
        rp_origin: impl Into<String>,
        challenge_ttl: Duration,
        session_ttl_secs: i64,
    ) -> Result<Self> {
        let rp_id = rp_id.into();
        let rp_origin = rp_origin.into();
        let origin = Url::parse(&rp_origin)
            .map_err(|e| AuthError::Internal(format!("invalid rp origin: {e}")))?;
        let webauthn = WebauthnBuilder::new(&rp_id, &origin)
            .map_err(|e| AuthError::Internal(format!("invalid webauthn config: {e}")))?
            .timeout(challenge_ttl)
            .build()
            .map_err(|e| AuthError::Internal(format!("invalid webauthn builder config: {e}")))?;

        Ok(Self {
            storage,
            webauthn,
            challenge_ttl,
            session_ttl_secs,
            pending: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    #[instrument(skip(self), fields(user_id = %user_id))]
    pub async fn begin_registration(&self, user_id: Uuid) -> Result<WebAuthnBeginResponse> {
        let user = UserRepository::find_by_id(&self.storage, user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let exclude_credentials = self
            .stored_passkey(user_id)
            .await?
            .map(|passkey| vec![passkey.cred_id().clone()]);

        let (creation, state) = self
            .webauthn
            .start_passkey_registration(user.id, &user.email, &user.email, exclude_credentials)
            .map_err(|e| AuthError::Internal(format!("start passkey registration failed: {e}")))?;

        let ceremony_id = self.store_registration_state(user_id, state)?;
        Ok(WebAuthnBeginResponse {
            challenge: ceremony_id,
            user_id,
            timeout_secs: self.challenge_ttl.as_secs(),
            options: creation_challenge_to_json(creation)?,
        })
    }

    #[instrument(skip(self, req))]
    pub async fn finish_registration(
        &self,
        req: FinishRegistrationRequest,
    ) -> Result<WebAuthnRegistrationResult> {
        let (user_id, state) = self.take_registration_state(&req.challenge)?;
        let passkey = self
            .webauthn
            .finish_passkey_registration(&req.credential, &state)
            .map_err(|_| AuthError::InvalidToken)?;

        self.persist_passkey(user_id, passkey).await?;

        tracing::info!(user_id = %user_id, "webauthn credential registered");
        Ok(WebAuthnRegistrationResult {
            user_id,
            credential_stored: true,
        })
    }

    #[instrument(skip(self), fields(user_id = %user_id))]
    pub async fn begin_authentication(&self, user_id: Uuid) -> Result<WebAuthnBeginResponse> {
        let _ = UserRepository::find_by_id(&self.storage, user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let passkey = self
            .stored_passkey(user_id)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;
        let (request, state) = self
            .webauthn
            .start_passkey_authentication(std::slice::from_ref(&passkey))
            .map_err(|e| {
                AuthError::Internal(format!("start passkey authentication failed: {e}"))
            })?;

        let ceremony_id = self.store_authentication_state(user_id, state, passkey)?;
        Ok(WebAuthnBeginResponse {
            challenge: ceremony_id,
            user_id,
            timeout_secs: self.challenge_ttl.as_secs(),
            options: request_challenge_to_json(request)?,
        })
    }

    #[instrument(skip(self, req))]
    pub async fn finish_authentication(
        &self,
        req: FinishAuthenticationRequest,
    ) -> Result<WebAuthnAuthenticationResult> {
        let (user_id, state, mut passkey) = self.take_authentication_state(&req.challenge)?;
        let auth_result = self
            .webauthn
            .finish_passkey_authentication(&req.credential, &state)
            .map_err(|_| AuthError::InvalidCredentials)?;

        let _ = passkey.update_credential(&auth_result);
        self.persist_passkey(user_id, passkey).await?;

        let raw_token = generate_token();
        let token_hash = sha256_hex(raw_token.as_bytes());
        let session = SessionRepository::create(
            &self.storage,
            CreateSession {
                user_id,
                token_hash,
                device_info: serde_json::json!({ "webauthn": true }),
                ip_address: req.ip,
                org_id: None,
                expires_at: Utc::now() + chrono::Duration::seconds(self.session_ttl_secs),
            },
        )
        .await?;

        tracing::info!(user_id = %user_id, session_id = %session.id, "webauthn sign-in complete");
        Ok(WebAuthnAuthenticationResult {
            user_id,
            session_id: session.id,
            token: raw_token,
        })
    }

    async fn persist_passkey(&self, user_id: Uuid, passkey: Passkey) -> Result<()> {
        let serialized = serde_json::to_value(passkey)
            .map_err(|e| AuthError::Internal(format!("serialize passkey failed: {e}")))?;
        let cred_hash = sha256_hex(
            serde_json::to_string(&serialized)
                .map_err(|e| AuthError::Internal(format!("encode passkey failed: {e}")))?
                .as_bytes(),
        );

        self.delete_existing_webauthn_credential(user_id).await?;
        CredentialRepository::create(
            &self.storage,
            CreateCredential {
                user_id,
                kind: CredentialKind::Webauthn,
                credential_hash: cred_hash,
                metadata: Some(serde_json::json!({
                    "passkey": serialized,
                    "updated_at": Utc::now(),
                })),
            },
        )
        .await?;
        Ok(())
    }

    async fn stored_passkey(&self, user_id: Uuid) -> Result<Option<Passkey>> {
        let credential = CredentialRepository::find_by_user_and_kind(
            &self.storage,
            user_id,
            CredentialKind::Webauthn,
        )
        .await?;
        let Some(credential) = credential else {
            return Ok(None);
        };

        let passkey_value = credential
            .metadata
            .get("passkey")
            .cloned()
            .ok_or(AuthError::InvalidCredentials)?;
        let passkey =
            serde_json::from_value(passkey_value).map_err(|_| AuthError::InvalidCredentials)?;
        Ok(Some(passkey))
    }

    async fn delete_existing_webauthn_credential(&self, user_id: Uuid) -> Result<()> {
        match CredentialRepository::delete_by_user_and_kind(
            &self.storage,
            user_id,
            CredentialKind::Webauthn,
        )
        .await
        {
            Ok(()) | Err(AuthError::Storage(StorageError::NotFound)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn store_registration_state(
        &self,
        user_id: Uuid,
        state: PasskeyRegistration,
    ) -> Result<String> {
        let ceremony_id = generate_token();
        let mut pending = self
            .pending
            .write()
            .map_err(|e| AuthError::Internal(format!("webauthn ceremony lock poisoned: {e}")))?;
        purge_expired(&mut pending);
        pending.insert(
            ceremony_id.clone(),
            PendingCeremony::Registration {
                user_id,
                state,
                expires_at: Instant::now() + self.challenge_ttl,
            },
        );
        Ok(ceremony_id)
    }

    fn store_authentication_state(
        &self,
        user_id: Uuid,
        state: PasskeyAuthentication,
        passkey: Passkey,
    ) -> Result<String> {
        let ceremony_id = generate_token();
        let mut pending = self
            .pending
            .write()
            .map_err(|e| AuthError::Internal(format!("webauthn ceremony lock poisoned: {e}")))?;
        purge_expired(&mut pending);
        pending.insert(
            ceremony_id.clone(),
            PendingCeremony::Authentication {
                user_id,
                state,
                passkey,
                expires_at: Instant::now() + self.challenge_ttl,
            },
        );
        Ok(ceremony_id)
    }

    fn take_registration_state(&self, ceremony_id: &str) -> Result<(Uuid, PasskeyRegistration)> {
        let mut pending = self
            .pending
            .write()
            .map_err(|e| AuthError::Internal(format!("webauthn ceremony lock poisoned: {e}")))?;
        let Some(ceremony) = pending.remove(ceremony_id) else {
            return Err(AuthError::InvalidToken);
        };

        match ceremony {
            PendingCeremony::Registration {
                user_id,
                state,
                expires_at,
            } if expires_at >= Instant::now() => Ok((user_id, state)),
            _ => Err(AuthError::InvalidToken),
        }
    }

    fn take_authentication_state(
        &self,
        ceremony_id: &str,
    ) -> Result<(Uuid, PasskeyAuthentication, Passkey)> {
        let mut pending = self
            .pending
            .write()
            .map_err(|e| AuthError::Internal(format!("webauthn ceremony lock poisoned: {e}")))?;
        let Some(ceremony) = pending.remove(ceremony_id) else {
            return Err(AuthError::InvalidToken);
        };

        match ceremony {
            PendingCeremony::Authentication {
                user_id,
                state,
                passkey,
                expires_at,
            } if expires_at >= Instant::now() => Ok((user_id, state, passkey)),
            _ => Err(AuthError::InvalidToken),
        }
    }
}

fn creation_challenge_to_json(challenge: CreationChallengeResponse) -> Result<serde_json::Value> {
    serde_json::to_value(challenge)
        .map_err(|e| AuthError::Internal(format!("serialize registration challenge failed: {e}")))
}

fn request_challenge_to_json(challenge: RequestChallengeResponse) -> Result<serde_json::Value> {
    serde_json::to_value(challenge)
        .map_err(|e| AuthError::Internal(format!("serialize authentication challenge failed: {e}")))
}

fn generate_token() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(bytes)
}

fn purge_expired(pending: &mut HashMap<String, PendingCeremony>) {
    let now = Instant::now();
    pending.retain(|_, ceremony| match ceremony {
        PendingCeremony::Registration { expires_at, .. }
        | PendingCeremony::Authentication { expires_at, .. } => *expires_at >= now,
    });
}
