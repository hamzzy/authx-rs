use super::*;
use authx_storage::memory::MemoryStore;
use chrono::Utc;

fn store() -> MemoryStore { MemoryStore::new() }

async fn create_user(store: &MemoryStore) -> Uuid {
    use authx_core::models::CreateUser;
    use authx_storage::ports::UserRepository;
    UserRepository::create(store, CreateUser { email: "k@example.com".into(), username: None, metadata: None })
        .await
        .unwrap()
        .id
}

#[tokio::test]
async fn create_returns_raw_key() {
    let s = store();
    let uid = create_user(&s).await;
    let svc = ApiKeyService::new(s);
    let resp = svc.create(uid, None, "test".into(), vec![], None).await.unwrap();
    assert_eq!(resp.raw_key.len(), 64); // 32 bytes hex-encoded
    assert!(!resp.key.key_hash.is_empty());
    assert_eq!(&resp.raw_key[..8], resp.key.prefix);
}

#[tokio::test]
async fn list_returns_created_keys() {
    let s = store();
    let uid = create_user(&s).await;
    let svc = ApiKeyService::new(s);
    svc.create(uid, None, "k1".into(), vec![], None).await.unwrap();
    svc.create(uid, None, "k2".into(), vec![], None).await.unwrap();
    let keys = svc.list(uid).await.unwrap();
    assert_eq!(keys.len(), 2);
}

#[tokio::test]
async fn revoke_removes_key() {
    let s = store();
    let uid = create_user(&s).await;
    let svc = ApiKeyService::new(s);
    let resp = svc.create(uid, None, "k".into(), vec![], None).await.unwrap();
    svc.revoke(uid, resp.key.id).await.unwrap();
    let keys = svc.list(uid).await.unwrap();
    assert!(keys.is_empty());
}

#[tokio::test]
async fn authenticate_valid_key() {
    let s = store();
    let uid = create_user(&s).await;
    let svc = ApiKeyService::new(s);
    let resp = svc.create(uid, None, "k".into(), vec!["read".into()], None).await.unwrap();
    let key = svc.authenticate(&resp.raw_key).await.unwrap();
    assert_eq!(key.user_id, uid);
    assert!(key.last_used_at.is_some());
}

#[tokio::test]
async fn authenticate_expired_key_fails() {
    let s = store();
    let uid = create_user(&s).await;
    let svc = ApiKeyService::new(s.clone());
    let past = Utc::now() - chrono::Duration::hours(1);
    let resp = svc.create(uid, None, "k".into(), vec![], Some(past)).await.unwrap();
    assert!(svc.authenticate(&resp.raw_key).await.is_err());
}
