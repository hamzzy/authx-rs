pub mod github;
pub mod google;

use async_trait::async_trait;

use authx_core::error::Result;

/// OAuth tokens returned from the authorization server.
#[derive(Debug, Clone)]
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Token lifetime in seconds as reported by the server, if present.
    pub expires_in: Option<u64>,
}

/// Normalized user info fetched from the provider's user-info endpoint.
#[derive(Debug, Clone)]
pub struct OAuthUserInfo {
    pub provider_user_id: String,
    pub email: String,
    pub name: Option<String>,
}

#[async_trait]
pub trait OAuthProvider: Send + Sync {
    fn name(&self) -> &'static str;

    /// Build the provider authorization URL the user should be redirected to.
    fn authorization_url(&self, state: &str, pkce_challenge: &str) -> String;

    /// Exchange the authorization code for tokens.
    async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: &str,
        redirect_uri: &str,
    ) -> Result<OAuthTokens>;

    /// Fetch user info using the access token.
    async fn fetch_user_info(&self, access_token: &str) -> Result<OAuthUserInfo>;
}
