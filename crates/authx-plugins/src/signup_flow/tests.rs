use authx_core::events::EventBus;
use authx_storage::memory::MemoryStore;

use super::service::{SignupFlowRequest, SignupFlowService};

#[tokio::test]
async fn signup_flow_issues_verification_token_and_optional_totp_setup() {
    let svc = SignupFlowService::new(MemoryStore::new(), EventBus::new(), 8, 3600, "authx-test");

    let resp = svc
        .sign_up(SignupFlowRequest {
            email: "flow@example.com".into(),
            password: "StrongPass1!".into(),
            ip: "127.0.0.1".into(),
            setup_mfa: true,
        })
        .await
        .unwrap();

    assert_eq!(resp.user.email, "flow@example.com");
    assert!(!resp.email_verification_token.is_empty());
    assert!(resp.totp_setup.is_some());
}
