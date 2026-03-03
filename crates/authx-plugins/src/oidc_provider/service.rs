//! OIDC Provider service — authx acts as Identity Provider and OAuth2 authorization server.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use rand::Rng;
use sha2::{Digest, Sha256};
use tracing::instrument;
use uuid::Uuid;

use authx_core::{
    crypto::sha256_hex,
    error::{AuthError, Result},
    models::{CreateAuthorizationCode, CreateDeviceCode, CreateOidcToken, OidcTokenType},
    KeyRotationStore,
};
use authx_storage::ports::{
    AuthorizationCodeRepository, DeviceCodeRepository, OidcClientRepository, OidcTokenRepository,
    UserRepository,
};

/// Configuration for the OIDC Provider.
#[derive(Clone)]
pub struct OidcProviderConfig {
    pub issuer: String,
    pub key_store: KeyRotationStore,
    pub access_token_ttl_secs: i64,
    pub id_token_ttl_secs: i64,
    pub refresh_token_ttl_secs: i64,
    pub auth_code_ttl_secs: i64,
    /// Device code lifetime in seconds (default 600 = 10 min).
    pub device_code_ttl_secs: i64,
    /// Minimum polling interval in seconds (default 5).
    pub device_code_interval_secs: u32,
    /// User-facing verification URI (e.g. "https://example.com/device").
    pub verification_uri: String,
}

/// Response from the token endpoint.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct OidcTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

/// Response from the device authorization endpoint (RFC 8628 Section 3.2).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_uri_complete: Option<String>,
    pub expires_in: i64,
    pub interval: u32,
}

/// Error type specific to device code polling (RFC 8628 Section 3.5).
#[derive(Debug, Clone)]
pub enum DeviceCodeError {
    AuthorizationPending,
    SlowDown,
    ExpiredToken,
    AccessDenied,
}

/// OIDC Provider service — authx as IdP.
pub struct OidcProviderService<S> {
    storage: S,
    config: OidcProviderConfig,
}

impl<S> OidcProviderService<S>
where
    S: OidcClientRepository
        + AuthorizationCodeRepository
        + OidcTokenRepository
        + DeviceCodeRepository
        + UserRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    pub fn new(storage: S, config: OidcProviderConfig) -> Self {
        Self { storage, config }
    }

    /// Validate authorize request and create authorization code. Caller must ensure user is authenticated.
    #[instrument(skip(self))]
    pub async fn create_authorization_code(
        &self,
        user_id: Uuid,
        client_id: &str,
        redirect_uri: &str,
        scope: &str,
        state: Option<&str>,
        nonce: Option<&str>,
        code_challenge: Option<&str>,
    ) -> Result<(String, String)> {
        let client = OidcClientRepository::find_by_client_id(&self.storage, client_id)
            .await?
            .ok_or(AuthError::Internal("invalid client_id".into()))?;

        if !client.redirect_uris.iter().any(|u| u == redirect_uri) {
            return Err(AuthError::Internal("redirect_uri not allowed".into()));
        }
        if !client.response_types.contains(&"code".to_string()) {
            return Err(AuthError::Internal("response_type code not allowed".into()));
        }

        let allowed: std::collections::HashSet<_> =
            client.allowed_scopes.split_whitespace().collect();
        for s in scope.split_whitespace() {
            if s != "openid" && !allowed.contains(s) {
                return Err(AuthError::Internal(format!("scope {s} not allowed")));
            }
        }

        // Generate one-time code
        let raw_code: [u8; 32] = rand::thread_rng().gen();
        let code = URL_SAFE_NO_PAD.encode(raw_code);
        let code_hash = sha256_hex(code.as_bytes());

        let _auth_code = AuthorizationCodeRepository::create(
            &self.storage,
            CreateAuthorizationCode {
                code_hash: code_hash.clone(),
                client_id: client_id.to_string(),
                user_id,
                redirect_uri: redirect_uri.to_string(),
                scope: scope.to_string(),
                nonce: nonce.map(str::to_string),
                code_challenge: code_challenge.map(str::to_string),
                expires_at: Utc::now() + Duration::seconds(self.config.auth_code_ttl_secs),
            },
        )
        .await?;

        let redirect = if let Some(st) = state {
            format!("{redirect_uri}?code={code}&state={st}")
        } else {
            format!("{redirect_uri}?code={code}")
        };
        Ok((code, redirect))
    }

    /// Exchange authorization code for tokens.
    #[instrument(skip(self, client_secret))]
    pub async fn exchange_code(
        &self,
        code: &str,
        client_id: &str,
        client_secret: Option<&str>,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> Result<OidcTokenResponse> {
        let code_hash = sha256_hex(code.as_bytes());
        let auth_code = AuthorizationCodeRepository::find_by_code_hash(&self.storage, &code_hash)
            .await?
            .ok_or(AuthError::InvalidToken)?;

        if auth_code.client_id != client_id {
            return Err(AuthError::InvalidToken);
        }
        if auth_code.redirect_uri != redirect_uri {
            return Err(AuthError::InvalidToken);
        }

        let client = OidcClientRepository::find_by_client_id(&self.storage, client_id)
            .await?
            .ok_or(AuthError::InvalidToken)?;

        if !client.secret_hash.is_empty() {
            let secret = client_secret.ok_or(AuthError::InvalidToken)?;
            let hash = sha256_hex(secret.as_bytes());
            use subtle::ConstantTimeEq;
            if hash
                .as_bytes()
                .ct_eq(client.secret_hash.as_bytes())
                .unwrap_u8()
                == 0
            {
                return Err(AuthError::InvalidToken);
            }
        } else if let Some(challenge) = &auth_code.code_challenge {
            let verifier = code_verifier.ok_or(AuthError::InvalidToken)?;
            let mut hasher = Sha256::new();
            hasher.update(verifier.as_bytes());
            let computed = URL_SAFE_NO_PAD.encode(hasher.finalize());
            if computed != *challenge {
                return Err(AuthError::InvalidToken);
            }
        }

        AuthorizationCodeRepository::mark_used(&self.storage, auth_code.id).await?;

        self.issue_tokens(
            auth_code.user_id,
            client_id,
            &auth_code.scope,
            auth_code.nonce.as_deref(),
        )
        .await
    }

    /// Exchange refresh token for new tokens.
    #[instrument(skip(self, client_secret))]
    pub async fn refresh(
        &self,
        refresh_token: &str,
        client_id: &str,
        client_secret: Option<&str>,
        scope: Option<&str>,
    ) -> Result<OidcTokenResponse> {
        let token_hash = sha256_hex(refresh_token.as_bytes());
        let token = OidcTokenRepository::find_by_token_hash(&self.storage, &token_hash)
            .await?
            .ok_or(AuthError::InvalidToken)?;

        if token.client_id != client_id || token.token_type != OidcTokenType::Refresh {
            return Err(AuthError::InvalidToken);
        }

        let client = OidcClientRepository::find_by_client_id(&self.storage, client_id)
            .await?
            .ok_or(AuthError::InvalidToken)?;

        if !client.secret_hash.is_empty() {
            let secret = client_secret.ok_or(AuthError::InvalidToken)?;
            let hash = sha256_hex(secret.as_bytes());
            use subtle::ConstantTimeEq;
            if hash
                .as_bytes()
                .ct_eq(client.secret_hash.as_bytes())
                .unwrap_u8()
                == 0
            {
                return Err(AuthError::InvalidToken);
            }
        }

        OidcTokenRepository::revoke(&self.storage, token.id).await?;

        let token_scope = scope.unwrap_or(&token.scope);
        self.issue_tokens(token.user_id, client_id, token_scope, None)
            .await
    }

    async fn issue_tokens(
        &self,
        user_id: Uuid,
        client_id: &str,
        scope: &str,
        nonce: Option<&str>,
    ) -> Result<OidcTokenResponse> {
        let user = UserRepository::find_by_id(&self.storage, user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let now = Utc::now();
        let access_ttl = self.config.access_token_ttl_secs;
        let id_ttl = self.config.id_token_ttl_secs.min(access_ttl);

        let access_extra = serde_json::json!({
            "iss": self.config.issuer,
            "aud": client_id,
            "scope": scope
        });
        let access_token = self
            .config
            .key_store
            .sign(user_id, access_ttl, access_extra)?;

        let id_token = if scope.split_whitespace().any(|s| s == "openid") {
            let mut id_extra = serde_json::json!({
                "iss": self.config.issuer,
                "aud": client_id
            });
            if let Some(n) = nonce {
                id_extra["nonce"] = serde_json::Value::String(n.to_string());
            }
            if scope.contains("email") {
                id_extra["email"] = serde_json::Value::String(user.email.clone());
                id_extra["email_verified"] = serde_json::Value::Bool(user.email_verified);
            }
            if scope.contains("profile") {
                id_extra["name"] = serde_json::Value::String(user.email.clone());
                if let Some(ref u) = user.username {
                    id_extra["preferred_username"] = serde_json::Value::String(u.clone());
                }
            }
            Some(self.config.key_store.sign(user_id, id_ttl, id_extra)?)
        } else {
            None
        };

        let refresh_token = if scope.split_whitespace().any(|s| s == "offline_access")
            || !scope.is_empty()
        {
            let raw: [u8; 32] = rand::thread_rng().gen();
            let token = hex::encode(raw);
            let token_hash = sha256_hex(token.as_bytes());

            OidcTokenRepository::create(
                &self.storage,
                CreateOidcToken {
                    token_hash,
                    client_id: client_id.to_string(),
                    user_id,
                    scope: scope.to_string(),
                    token_type: OidcTokenType::Refresh,
                    expires_at: Some(now + Duration::seconds(self.config.refresh_token_ttl_secs)),
                },
            )
            .await?;
            Some(token)
        } else {
            None
        };

        Ok(OidcTokenResponse {
            access_token,
            token_type: "Bearer".into(),
            expires_in: access_ttl,
            refresh_token,
            scope: Some(scope.to_string()),
            id_token,
        })
    }

    /// Validate Bearer access token and return user ID for UserInfo.
    pub fn validate_access_token(&self, token: &str) -> Result<Uuid> {
        let claims = self.config.key_store.verify(token)?;
        Uuid::parse_str(&claims.sub).map_err(|_| AuthError::InvalidToken)
    }

    /// Validate access token and return UserInfo claims as JSON.
    pub async fn userinfo(&self, access_token: &str) -> Result<serde_json::Value> {
        let user_id = self.validate_access_token(access_token)?;
        let user = UserRepository::find_by_id(&self.storage, user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let mut claims = serde_json::json!({
            "sub": user.id.to_string(),
            "email": user.email,
            "email_verified": user.email_verified,
        });
        if let Some(ref u) = user.username {
            claims["preferred_username"] = serde_json::Value::String(u.clone());
        }
        Ok(claims)
    }

    // ── Device Authorization Grant (RFC 8628) ─────────────────────────────

    /// Step 1: Device requests authorization. Returns device_code, user_code, etc.
    #[instrument(skip(self))]
    pub async fn request_device_authorization(
        &self,
        client_id: &str,
        scope: &str,
    ) -> Result<DeviceAuthorizationResponse> {
        // Validate client exists
        let client = OidcClientRepository::find_by_client_id(&self.storage, client_id)
            .await?
            .ok_or(AuthError::Internal("invalid client_id".into()))?;

        // Validate scopes
        let allowed: std::collections::HashSet<_> =
            client.allowed_scopes.split_whitespace().collect();
        for s in scope.split_whitespace() {
            if s != "openid" && !allowed.contains(s) {
                return Err(AuthError::Internal(format!("scope {s} not allowed")));
            }
        }

        // Generate high-entropy device_code (32 bytes, base64url)
        let raw_device_code: [u8; 32] = rand::thread_rng().gen();
        let device_code = URL_SAFE_NO_PAD.encode(raw_device_code);
        let device_code_hash = sha256_hex(device_code.as_bytes());

        // Generate human-typeable user_code (XXXX-XXXX)
        let user_code = generate_user_code();
        let user_code_hash = sha256_hex(user_code.replace('-', "").as_bytes());

        let expires_at = Utc::now() + Duration::seconds(self.config.device_code_ttl_secs);

        DeviceCodeRepository::create(
            &self.storage,
            CreateDeviceCode {
                device_code_hash,
                user_code_hash,
                user_code: user_code.clone(),
                client_id: client_id.to_string(),
                scope: scope.to_string(),
                expires_at,
                interval_secs: self.config.device_code_interval_secs,
            },
        )
        .await?;

        let verification_uri_complete = Some(format!(
            "{}?user_code={}",
            self.config.verification_uri, user_code
        ));

        Ok(DeviceAuthorizationResponse {
            device_code,
            user_code,
            verification_uri: self.config.verification_uri.clone(),
            verification_uri_complete,
            expires_in: self.config.device_code_ttl_secs,
            interval: self.config.device_code_interval_secs,
        })
    }

    /// Step 2: User approves or denies the device code via the verification page.
    #[instrument(skip(self))]
    pub async fn verify_user_code(
        &self,
        user_code: &str,
        user_id: Uuid,
        approve: bool,
    ) -> Result<()> {
        let normalized = user_code.replace('-', "").to_uppercase();
        let user_code_hash = sha256_hex(normalized.as_bytes());

        let dc = DeviceCodeRepository::find_by_user_code_hash(&self.storage, &user_code_hash)
            .await?
            .ok_or(AuthError::Internal("invalid or expired user_code".into()))?;

        if approve {
            DeviceCodeRepository::authorize(&self.storage, dc.id, user_id).await?;
        } else {
            DeviceCodeRepository::deny(&self.storage, dc.id).await?;
        }

        Ok(())
    }

    /// Step 3: Device polls for token. Returns tokens on success or a DeviceCodeError.
    #[instrument(skip(self))]
    pub async fn poll_device_code(
        &self,
        device_code: &str,
        client_id: &str,
    ) -> std::result::Result<OidcTokenResponse, DeviceCodeError> {
        let device_code_hash = sha256_hex(device_code.as_bytes());

        let dc = DeviceCodeRepository::find_by_device_code_hash(&self.storage, &device_code_hash)
            .await
            .map_err(|_| DeviceCodeError::ExpiredToken)?
            .ok_or(DeviceCodeError::ExpiredToken)?;

        if dc.client_id != client_id {
            return Err(DeviceCodeError::ExpiredToken);
        }

        // Check rate limit (slow_down per RFC 8628 Section 3.5)
        if let Some(last) = dc.last_polled_at {
            let elapsed = (Utc::now() - last).num_seconds();
            if elapsed < dc.interval_secs as i64 {
                let new_interval = dc.interval_secs + 5;
                let _ =
                    DeviceCodeRepository::update_last_polled(&self.storage, dc.id, new_interval)
                        .await;
                return Err(DeviceCodeError::SlowDown);
            }
        }

        // Update last_polled_at
        let _ =
            DeviceCodeRepository::update_last_polled(&self.storage, dc.id, dc.interval_secs).await;

        // Check denied
        if dc.denied {
            return Err(DeviceCodeError::AccessDenied);
        }

        // Check authorized
        if !dc.authorized {
            return Err(DeviceCodeError::AuthorizationPending);
        }

        // User authorized — issue tokens
        let user_id = dc.user_id.ok_or(DeviceCodeError::AccessDenied)?;
        self.issue_tokens(user_id, client_id, &dc.scope, None)
            .await
            .map_err(|_| DeviceCodeError::AccessDenied)
    }
}

/// Generate an 8-character user code like "BDWD-HQPK".
/// Uses uppercase letters excluding ambiguous chars (0, O, 1, I, L).
fn generate_user_code() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    let code: String = (0..8)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    format!("{}-{}", &code[..4], &code[4..])
}
