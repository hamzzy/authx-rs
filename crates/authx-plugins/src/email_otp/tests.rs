use super::*;
use authx_core::{events::EventBus, models::CreateUser};
use authx_storage::{memory::MemoryStore, ports::UserRepository};

fn setup(store: MemoryStore) -> EmailOtpService<MemoryStore> {
    EmailOtpService::new(store, EventBus::new(), 3600)
}

async fn add_user(store: &MemoryStore) -> authx_core::models::User {
    UserRepository::create(
        store,
        CreateUser { email: "otp@example.com".into(), username: None, metadata: None },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn unknown_email_returns_none() {
    let svc = setup(MemoryStore::new());
    assert!(svc.issue("nobody@example.com").await.unwrap().is_none());
}

#[tokio::test]
async fn known_email_returns_token() {
    let store = MemoryStore::new();
    add_user(&store).await;
    let svc = setup(store);
    let token = svc.issue("otp@example.com").await.unwrap();
    assert!(token.is_some());
}

#[tokio::test]
async fn verify_creates_session() {
    let store = MemoryStore::new();
    add_user(&store).await;
    let svc   = setup(store);
    let token = svc.issue("otp@example.com").await.unwrap().unwrap();
    let resp  = svc.verify(&token, "127.0.0.1").await.unwrap();
    assert!(!resp.token.is_empty());
    assert_eq!(resp.session.ip_address, "127.0.0.1");
}

#[tokio::test]
async fn verify_is_single_use() {
    let store = MemoryStore::new();
    add_user(&store).await;
    let svc   = setup(store);
    let token = svc.issue("otp@example.com").await.unwrap().unwrap();
    svc.verify(&token, "127.0.0.1").await.unwrap();
    assert!(svc.verify(&token, "127.0.0.1").await.is_err());
}
