use super::*;
use authx_core::events::EventBus;
use authx_storage::memory::MemoryStore;

fn svc(store: MemoryStore) -> UsernameService<MemoryStore> {
    UsernameService::new(store, EventBus::new(), 3600)
}

#[tokio::test]
async fn sign_up_creates_user() {
    let store = MemoryStore::new();
    let s = svc(store);
    let user = s
        .sign_up("alice", "alice@example.com", "hunter2!")
        .await
        .unwrap();
    assert_eq!(user.username.as_deref(), Some("alice"));
}

#[tokio::test]
async fn duplicate_username_rejected() {
    let store = MemoryStore::new();
    let s = svc(store);
    s.sign_up("bob", "bob@example.com", "password1")
        .await
        .unwrap();
    assert!(s
        .sign_up("bob", "bob2@example.com", "password2")
        .await
        .is_err());
}

#[tokio::test]
async fn sign_in_succeeds() {
    let store = MemoryStore::new();
    let s = svc(store);
    s.sign_up("carol", "carol@example.com", "correcthorse")
        .await
        .unwrap();
    let resp = s
        .sign_in("carol", "correcthorse", "127.0.0.1")
        .await
        .unwrap();
    assert!(!resp.token.is_empty());
}

#[tokio::test]
async fn sign_in_wrong_password_fails() {
    let store = MemoryStore::new();
    let s = svc(store);
    s.sign_up("dave", "dave@example.com", "rightpass")
        .await
        .unwrap();
    assert!(s.sign_in("dave", "wrongpass", "127.0.0.1").await.is_err());
}
