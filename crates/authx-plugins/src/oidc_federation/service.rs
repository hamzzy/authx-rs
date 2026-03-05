//! OIDC Federation — sign in via external IdPs (Okta, Azure AD, Google Workspace).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use rand::Rng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::instrument;

use authx_core::{
    crypto::{decrypt, encrypt, sha256_hex},
    error::{AuthError, Result},
    models::{CreateSession, CreateUser, Session, UpsertOAuthAccount, User},
};
use authx_storage::ports::{
    OAuthAccountRepository, OidcFederationProviderRepository, SessionRepository, UserRepository,
};

/// Response from begin() — redirect the user to authorization_url.
#[derive(Debug)]
pub struct OidcFederationBeginResponse {
    pub authorization_url: String,
    pub state: String,
    pub code_verifier: String,
}

/// Discovered OIDC provider configuration.
#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    userinfo_endpoint: Option<String>,
}

/// UserInfo from OIDC IdP.
#[derive(Debug, Deserialize)]
pub struct OidcUserInfo {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
}

/// Stored federation flow state (code_verifier + redirect_uri).
struct FederationState {
    code_verifier: String,
    redirect_uri: String,
    expires_at: Instant,
}

/// OIDC Federation service — sign in via Okta, Azure AD, Google Workspace, etc.
pub struct OidcFederationService<S> {
    storage: S,
    session_ttl_secs: i64,
    encryption_key: [u8; 32],
    client: reqwest::Client,
    /// state -> (code_verifier, redirect_uri) for callback lookup.
    pending: Arc<std::sync::RwLock<HashMap<String, FederationState>>>,
}

impl<S> OidcFederationService<S>
where
    S: OidcFederationProviderRepository
        + UserRepository
        + SessionRepository
        + OAuthAccountRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    pub fn new(storage: S, session_ttl_secs: i64, encryption_key: [u8; 32]) -> Self {
        Self {
            storage,
            session_ttl_secs,
            encryption_key,
            client: reqwest::Client::new(),
            pending: Arc::new(std::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Begin OIDC federation flow. Returns URL to redirect user to the IdP.
    #[instrument(skip(self))]
    pub async fn begin(
        &self,
        provider_name: &str,
        redirect_uri: &str,
    ) -> Result<OidcFederationBeginResponse> {
        let provider = OidcFederationProviderRepository::find_by_name(&self.storage, provider_name)
            .await?
            .ok_or_else(|| {
                AuthError::Internal(format!("unknown federation provider: {provider_name}"))
            })?;

        if !provider.enabled {
            return Err(AuthError::Internal("provider is disabled".into()));
        }

        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            provider.issuer.trim_end_matches('/')
        );
        let discovery: OidcDiscovery = self
            .client
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("oidc discovery failed: {e}")))?
            .json()
            .await
            .map_err(|e| AuthError::Internal(format!("oidc discovery parse failed: {e}")))?;

        let verifier_bytes: [u8; 32] = rand::thread_rng().gen();
        let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);
        let mut hasher = Sha256::new();
        hasher.update(code_verifier.as_bytes());
        let code_challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());

        let state_bytes: [u8; 16] = rand::thread_rng().gen();
        let state = hex::encode(state_bytes);

        {
            let mut pending = self
                .pending
                .write()
                .map_err(|e| AuthError::Internal(format!("lock poisoned: {e}")))?;
            pending.insert(
                state.clone(),
                FederationState {
                    code_verifier: code_verifier.clone(),
                    redirect_uri: redirect_uri.to_string(),
                    expires_at: Instant::now() + Duration::from_secs(600), // 10 min
                },
            );
        }

        let mut auth_url = reqwest::Url::parse(&discovery.authorization_endpoint)
            .map_err(|e| AuthError::Internal(format!("invalid auth endpoint: {e}")))?;
        auth_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &provider.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &provider.scopes)
            .append_pair("state", &state)
            .append_pair("code_challenge", &code_challenge)
            .append_pair("code_challenge_method", "S256");

        Ok(OidcFederationBeginResponse {
            authorization_url: auth_url.to_string(),
            state,
            code_verifier,
        })
    }

    /// Handle callback from IdP. Exchange code, get userinfo, find-or-create user, create session.
    /// Looks up code_verifier and redirect_uri from the pending state stored during begin().
    #[instrument(skip(self))]
    pub async fn callback(
        &self,
        provider_name: &str,
        code: &str,
        state: &str,
        ip: &str,
    ) -> Result<(User, Session, String)> {
        let (code_verifier, redirect_uri) = {
            let mut pending = self
                .pending
                .write()
                .map_err(|e| AuthError::Internal(format!("lock poisoned: {e}")))?;
            let entry = pending
                .remove(state)
                .ok_or(AuthError::InvalidToken)?;
            if entry.expires_at < Instant::now() {
                return Err(AuthError::InvalidToken);
            }
            (entry.code_verifier, entry.redirect_uri)
        };

        let provider = OidcFederationProviderRepository::find_by_name(&self.storage, provider_name)
            .await?
            .ok_or_else(|| {
                AuthError::Internal(format!("unknown federation provider: {provider_name}"))
            })?;

        let secret_bytes = decrypt(&self.encryption_key, &provider.secret_enc)
            .map_err(|e| AuthError::Internal(format!("decrypt client secret: {e}")))?;
        let secret = String::from_utf8(secret_bytes)
            .map_err(|_| AuthError::Internal("client secret not valid UTF-8".into()))?;

        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            provider.issuer.trim_end_matches('/')
        );
        let discovery: OidcDiscovery = self
            .client
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("oidc discovery: {e}")))?
            .json()
            .await
            .map_err(|e| AuthError::Internal(format!("oidc discovery parse: {e}")))?;

        let token_resp = self
            .client
            .post(&discovery.token_endpoint)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &redirect_uri),
                ("client_id", &provider.client_id),
                ("client_secret", &secret),
                ("code_verifier", &code_verifier),
            ])
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("token exchange: {e}")))?;

        if !token_resp.status().is_success() {
            let status = token_resp.status();
            let body = token_resp.text().await.unwrap_or_default();
            return Err(AuthError::Internal(format!(
                "token exchange failed {}: {}",
                status, body
            )));
        }

        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
        }
        let tokens: TokenResponse = token_resp
            .json()
            .await
            .map_err(|e| AuthError::Internal(format!("token parse: {e}")))?;

        let userinfo_endpoint = discovery
            .userinfo_endpoint
            .ok_or_else(|| AuthError::Internal("IdP has no userinfo endpoint".into()))?;

        let userinfo: OidcUserInfo = self
            .client
            .get(&userinfo_endpoint)
            .bearer_auth(&tokens.access_token)
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("userinfo: {e}")))?
            .json()
            .await
            .map_err(|e| AuthError::Internal(format!("userinfo parse: {e}")))?;

        let username = userinfo.preferred_username.clone();
        let email = userinfo
            .email
            .or(userinfo.preferred_username)
            .unwrap_or_else(|| format!("{}@{}", userinfo.sub, provider_name));

        let user = match UserRepository::find_by_email(&self.storage, &email).await? {
            Some(u) => u,
            None => {
                let u = UserRepository::create(
                    &self.storage,
                    CreateUser {
                        email: email.clone(),
                        username,
                        metadata: None,
                    },
                )
                .await?;
                u
            }
        };

        let access_enc = encrypt(&self.encryption_key, tokens.access_token.as_bytes())
            .map_err(|e| AuthError::Internal(format!("encrypt: {e}")))?;

        OAuthAccountRepository::upsert(
            &self.storage,
            UpsertOAuthAccount {
                user_id: user.id,
                provider: provider_name.to_string(),
                provider_user_id: userinfo.sub,
                access_token_enc: access_enc,
                refresh_token_enc: None,
                expires_at: None,
            },
        )
        .await?;

        let raw: [u8; 32] = rand::thread_rng().gen();
        let raw_str = hex::encode(raw);
        let token_hash = sha256_hex(raw_str.as_bytes());

        let session = SessionRepository::create(
            &self.storage,
            CreateSession {
                user_id: user.id,
                token_hash,
                device_info: serde_json::json!({ "oidc_federation": provider_name }),
                ip_address: ip.to_string(),
                org_id: None,
                expires_at: Utc::now() + chrono::Duration::seconds(self.session_ttl_secs),
            },
        )
        .await?;

        tracing::info!(user_id = %user.id, provider = provider_name, "oidc federation sign-in complete");
        Ok((user.clone(), session, raw_str))
    }
}
