use async_trait::async_trait;
use tracing::instrument;

use authx_core::error::{AuthError, Result};

use super::{OAuthProvider, OAuthTokens, OAuthUserInfo};

pub struct GitHubProvider {
    client_id:     String,
    client_secret: String,
    http:          reqwest::Client,
}

impl GitHubProvider {
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_id:     client_id.into(),
            client_secret: client_secret.into(),
            http:          reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl OAuthProvider for GitHubProvider {
    fn name(&self) -> &'static str { "github" }

    fn authorization_url(&self, state: &str, pkce_challenge: &str) -> String {
        format!(
            "https://github.com/login/oauth/authorize\
             ?client_id={}\
             &scope=read%3Auser%20user%3Aemail\
             &state={}\
             &code_challenge={}\
             &code_challenge_method=S256",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(state),
            urlencoding::encode(pkce_challenge),
        )
    }

    #[instrument(skip(self, code, pkce_verifier))]
    async fn exchange_code(&self, code: &str, pkce_verifier: &str, redirect_uri: &str) -> Result<OAuthTokens> {
        let res = self
            .http
            .post("https://github.com/login/oauth/access_token")
            .header("Accept", "application/json")
            .form(&[
                ("code",          code),
                ("client_id",     &self.client_id),
                ("client_secret", &self.client_secret),
                ("redirect_uri",  redirect_uri),
                ("code_verifier", pkce_verifier),
            ])
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("github token request failed: {e}")))?;

        if !res.status().is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(AuthError::Internal(format!("github token exchange error: {body}")));
        }

        let json: serde_json::Value = res
            .json()
            .await
            .map_err(|e| AuthError::Internal(format!("github token json: {e}")))?;

        if let Some(err) = json["error"].as_str() {
            return Err(AuthError::Internal(format!("github oauth error: {err}")));
        }

        tracing::debug!("github token exchange succeeded");
        Ok(OAuthTokens {
            access_token:  json["access_token"].as_str().unwrap_or("").to_owned(),
            refresh_token: json["refresh_token"].as_str().map(ToOwned::to_owned),
            expires_in:    json["expires_in"].as_u64(),
        })
    }

    #[instrument(skip(self, access_token))]
    async fn fetch_user_info(&self, access_token: &str) -> Result<OAuthUserInfo> {
        // Primary user endpoint.
        let user_res = self
            .http
            .get("https://api.github.com/user")
            .bearer_auth(access_token)
            .header("User-Agent", "authx-rs")
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("github user request failed: {e}")))?;

        if !user_res.status().is_success() {
            return Err(AuthError::Internal("github user fetch error".into()));
        }
        let user_json: serde_json::Value = user_res
            .json()
            .await
            .map_err(|e| AuthError::Internal(format!("github user json: {e}")))?;

        let id   = user_json["id"].as_u64().unwrap_or(0).to_string();
        let name = user_json["name"].as_str().map(ToOwned::to_owned);

        // Fetch primary verified email.
        let emails_res = self
            .http
            .get("https://api.github.com/user/emails")
            .bearer_auth(access_token)
            .header("User-Agent", "authx-rs")
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("github emails request failed: {e}")))?;

        let emails: Vec<serde_json::Value> = emails_res
            .json()
            .await
            .map_err(|e| AuthError::Internal(format!("github emails json: {e}")))?;

        let email = emails
            .iter()
            .find(|e| e["primary"].as_bool().unwrap_or(false) && e["verified"].as_bool().unwrap_or(false))
            .and_then(|e| e["email"].as_str())
            .or_else(|| user_json["email"].as_str())
            .ok_or_else(|| AuthError::Internal("github: no verified email found".into()))?
            .to_owned();

        tracing::debug!(provider = "github", "user info fetched");
        Ok(OAuthUserInfo { provider_user_id: id, email, name })
    }
}
