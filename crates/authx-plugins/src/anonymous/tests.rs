use super::*;
use authx_core::events::EventBus;
use authx_storage::memory::MemoryStore;

fn svc(store: MemoryStore) -> AnonymousService<MemoryStore> {
    AnonymousService::new(store, EventBus::new(), 3600)
}

#[tokio::test]
async fn create_guest_returns_session() {
    let store = MemoryStore::new();
    let s = svc(store);
    let guest = s.create_guest("10.0.0.1").await.unwrap();
    assert!(guest.user.email.starts_with("guest_"));
    assert!(!guest.token.is_empty());
    assert_eq!(guest.session.ip_address, "10.0.0.1");
}

#[tokio::test]
async fn upgrade_sets_real_email() {
    let store = MemoryStore::new();
    let s = svc(store.clone());
    let guest = s.create_guest("127.0.0.1").await.unwrap();
    let user = s
        .upgrade(guest.user.id, "real@example.com", "newpassword")
        .await
        .unwrap();
    assert_eq!(user.email, "real@example.com");
    assert_eq!(user.metadata["guest"], false);
}

#[tokio::test]
async fn upgrade_non_guest_forbidden() {
    use authx_core::models::CreateUser;
    use authx_storage::ports::UserRepository;
    let store = MemoryStore::new();
    let real = UserRepository::create(
        &store,
        CreateUser {
            email: "real@example.com".into(),
            username: None,
            metadata: None,
        },
    )
    .await
    .unwrap();
    let s = svc(store);
    assert!(s
        .upgrade(real.id, "other@example.com", "newpassword")
        .await
        .is_err());
}
