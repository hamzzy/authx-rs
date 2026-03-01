use async_trait::async_trait;
use tracing::instrument;

use authx_core::error::{AuthError, Result};

use super::{OAuthProvider, OAuthTokens, OAuthUserInfo};

pub struct GoogleProvider {
    client_id:     String,
    client_secret: String,
    http:          reqwest::Client,
}

impl GoogleProvider {
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_id:     client_id.into(),
            client_secret: client_secret.into(),
            http:          reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl OAuthProvider for GoogleProvider {
    fn name(&self) -> &'static str { "google" }

    fn authorization_url(&self, state: &str, pkce_challenge: &str) -> String {
        format!(
            "https://accounts.google.com/o/oauth2/v2/auth\
             ?client_id={}\
             &response_type=code\
             &scope=openid%20email%20profile\
             &redirect_uri=https%3A%2F%2Flocalhost%2Fauth%2Foauth%2Fgoogle%2Fcallback\
             &state={}\
             &code_challenge={}\
             &code_challenge_method=S256\
             &access_type=offline",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(state),
            urlencoding::encode(pkce_challenge),
        )
    }

    #[instrument(skip(self, code, pkce_verifier))]
    async fn exchange_code(&self, code: &str, pkce_verifier: &str, redirect_uri: &str) -> Result<OAuthTokens> {
        let res = self
            .http
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("code",          code),
                ("client_id",     &self.client_id),
                ("client_secret", &self.client_secret),
                ("redirect_uri",  redirect_uri),
                ("grant_type",    "authorization_code"),
                ("code_verifier", pkce_verifier),
            ])
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("google token request failed: {e}")))?;

        if !res.status().is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(AuthError::Internal(format!("google token exchange error: {body}")));
        }

        let json: serde_json::Value = res
            .json()
            .await
            .map_err(|e| AuthError::Internal(format!("google token json: {e}")))?;

        tracing::debug!("google token exchange succeeded");
        Ok(OAuthTokens {
            access_token:  json["access_token"].as_str().unwrap_or("").to_owned(),
            refresh_token: json["refresh_token"].as_str().map(ToOwned::to_owned),
            expires_in:    json["expires_in"].as_u64(),
        })
    }

    #[instrument(skip(self, access_token))]
    async fn fetch_user_info(&self, access_token: &str) -> Result<OAuthUserInfo> {
        let res = self
            .http
            .get("https://openidconnect.googleapis.com/v1/userinfo")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("google userinfo request failed: {e}")))?;

        if !res.status().is_success() {
            return Err(AuthError::Internal("google userinfo error".into()));
        }

        let json: serde_json::Value = res
            .json()
            .await
            .map_err(|e| AuthError::Internal(format!("google userinfo json: {e}")))?;

        let sub = json["sub"].as_str().ok_or_else(|| AuthError::Internal("missing sub".into()))?;
        let email = json["email"].as_str().ok_or_else(|| AuthError::Internal("missing email".into()))?;

        tracing::debug!(provider = "google", "user info fetched");
        Ok(OAuthUserInfo {
            provider_user_id: sub.to_owned(),
            email:            email.to_owned(),
            name:             json["name"].as_str().map(ToOwned::to_owned),
        })
    }
}
