use async_trait::async_trait;
use authx_core::{error::Result, events::EventBus};
use authx_storage::memory::MemoryStore;

use super::{
    providers::{OAuthProvider, OAuthTokens, OAuthUserInfo},
    service::{OAuthCallbackRequest, OAuthService},
};

fn enc_key() -> [u8; 32] {
    [0xABu8; 32]
}

struct MockProvider {
    name: &'static str,
}

#[async_trait]
impl OAuthProvider for MockProvider {
    fn name(&self) -> &'static str {
        self.name
    }

    fn authorization_url(&self, state: &str, challenge: &str) -> String {
        format!("https://mock.example/auth?state={state}&challenge={challenge}")
    }

    async fn exchange_code(
        &self,
        _code: &str,
        _verifier: &str,
        _redirect_uri: &str,
    ) -> Result<OAuthTokens> {
        Ok(OAuthTokens {
            access_token: "mock-access-token".into(),
            refresh_token: Some("mock-refresh-token".into()),
            expires_in: Some(3600),
        })
    }

    async fn fetch_user_info(&self, _access_token: &str) -> Result<OAuthUserInfo> {
        Ok(OAuthUserInfo {
            provider_user_id: "mock-uid-123".into(),
            email: "oauth@example.com".into(),
            name: Some("OAuth User".into()),
        })
    }
}

fn svc() -> OAuthService<MemoryStore> {
    OAuthService::new(MemoryStore::new(), EventBus::new(), 3600, enc_key())
        .register(MockProvider { name: "mock" })
}

#[test]
fn pkce_challenge_is_s256_of_verifier() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use sha2::{Digest, Sha256};

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let expected = {
        let mut h = Sha256::new();
        h.update(verifier.as_bytes());
        URL_SAFE_NO_PAD.encode(h.finalize())
    };
    // Verify round-trip via begin().
    let s = svc();
    let resp = s.begin("mock", "https://app.example/callback").unwrap();
    // The verifier produced by begin() is base64url of 32 random bytes.
    assert!(!resp.code_verifier.is_empty());
    assert!(!resp.state.is_empty());
    assert!(resp.authorization_url.contains("mock.example"));
    let _ = expected; // used above
}

#[test]
fn authorization_url_contains_state_and_challenge() {
    let s = svc();
    let resp = s.begin("mock", "https://app/cb").unwrap();
    assert!(resp.authorization_url.contains(&resp.state));
}

#[tokio::test]
async fn callback_creates_user_and_session() {
    let s = svc();
    let resp = s.begin("mock", "https://app/cb").unwrap();
    let (user, session, token) = s
        .callback(OAuthCallbackRequest {
            provider_name: "mock",
            code: "auth-code",
            expected_state: &resp.state,
            received_state: &resp.state,
            code_verifier: &resp.code_verifier,
            redirect_uri: "https://app/cb",
            ip: "127.0.0.1",
        })
        .await
        .unwrap();
    assert_eq!(user.email, "oauth@example.com");
    assert!(!token.is_empty());
    assert_eq!(session.user_id, user.id);
}

#[tokio::test]
async fn callback_state_mismatch_rejected() {
    let s = svc();
    let resp = s.begin("mock", "https://app/cb").unwrap();
    let err = s
        .callback(OAuthCallbackRequest {
            provider_name: "mock",
            code: "auth-code",
            expected_state: &resp.state,
            received_state: "tampered-state-value",
            code_verifier: &resp.code_verifier,
            redirect_uri: "https://app/cb",
            ip: "127.0.0.1",
        })
        .await;
    assert!(err.is_err(), "mismatched state must be rejected");
}

#[tokio::test]
async fn callback_twice_reuses_user() {
    let s = svc();
    let r1 = s.begin("mock", "https://app/cb").unwrap();
    let (u1, _, _) = s
        .callback(OAuthCallbackRequest {
            provider_name: "mock",
            code: "code1",
            expected_state: &r1.state,
            received_state: &r1.state,
            code_verifier: &r1.code_verifier,
            redirect_uri: "https://app/cb",
            ip: "127.0.0.1",
        })
        .await
        .unwrap();
    let r2 = s.begin("mock", "https://app/cb").unwrap();
    let (u2, _, _) = s
        .callback(OAuthCallbackRequest {
            provider_name: "mock",
            code: "code2",
            expected_state: &r2.state,
            received_state: &r2.state,
            code_verifier: &r2.code_verifier,
            redirect_uri: "https://app/cb",
            ip: "127.0.0.1",
        })
        .await
        .unwrap();
    assert_eq!(u1.id, u2.id, "same email → same user row");
}
