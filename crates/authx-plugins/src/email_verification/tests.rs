use super::*;
use authx_core::{events::EventBus, models::CreateUser};
use authx_storage::{memory::MemoryStore, ports::UserRepository};

async fn setup() -> (EmailVerificationService<MemoryStore>, Uuid) {
    let store  = MemoryStore::new();
    let events = EventBus::new();
    let user   = UserRepository::create(
        &store,
        CreateUser { email: "v@example.com".into(), username: None, metadata: None },
    )
    .await
    .unwrap();
    let svc = EmailVerificationService::new(store, events);
    (svc, user.id)
}

#[tokio::test]
async fn issue_returns_token() {
    let (svc, uid) = setup().await;
    let token = svc.issue(uid).await.unwrap();
    assert_eq!(token.len(), 64);
}

#[tokio::test]
async fn verify_sets_email_verified() {
    let store  = MemoryStore::new();
    let events = EventBus::new();
    let user = UserRepository::create(
        &store,
        CreateUser { email: "v@example.com".into(), username: None, metadata: None },
    )
    .await
    .unwrap();
    assert!(!user.email_verified);
    let svc = EmailVerificationService::new(store.clone(), events);
    let token = svc.issue(user.id).await.unwrap();
    svc.verify(&token).await.unwrap();
    let updated = UserRepository::find_by_id(&store, user.id).await.unwrap().unwrap();
    assert!(updated.email_verified);
}

#[tokio::test]
async fn verify_bad_token_fails() {
    let (svc, _) = setup().await;
    assert!(svc.verify("badtoken").await.is_err());
}

#[tokio::test]
async fn verify_is_single_use() {
    let (svc, uid) = setup().await;
    let token = svc.issue(uid).await.unwrap();
    svc.verify(&token).await.unwrap();
    assert!(svc.verify(&token).await.is_err());
}
