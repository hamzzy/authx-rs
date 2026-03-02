use super::*;
use authx_storage::memory::MemoryStore;
use chrono::Utc;
use uuid::Uuid;

fn store() -> MemoryStore {
    MemoryStore::new()
}

fn future() -> chrono::DateTime<Utc> {
    Utc::now() + chrono::Duration::days(30)
}

async fn create_user(store: &MemoryStore) -> Uuid {
    use authx_core::models::CreateUser;
    use authx_storage::ports::UserRepository;
    UserRepository::create(
        store,
        CreateUser {
            email: "k@example.com".into(),
            username: None,
            metadata: None,
        },
    )
    .await
    .unwrap()
    .id
}

#[tokio::test]
async fn create_returns_raw_key() {
    let s = store();
    let uid = create_user(&s).await;
    let svc = ApiKeyService::new(s);
    let resp = svc
        .create(uid, None, "test".into(), vec![], future())
        .await
        .unwrap();
    assert_eq!(resp.raw_key.len(), 64); // 32 bytes hex-encoded
    assert!(!resp.key.key_hash.is_empty());
    assert_eq!(&resp.raw_key[..8], resp.key.prefix);
}

#[tokio::test]
async fn list_returns_created_keys() {
    let s = store();
    let uid = create_user(&s).await;
    let svc = ApiKeyService::new(s);
    svc.create(uid, None, "k1".into(), vec![], future())
        .await
        .unwrap();
    svc.create(uid, None, "k2".into(), vec![], future())
        .await
        .unwrap();
    let keys = svc.list(uid).await.unwrap();
    assert_eq!(keys.len(), 2);
}

#[tokio::test]
async fn revoke_removes_key() {
    let s = store();
    let uid = create_user(&s).await;
    let svc = ApiKeyService::new(s);
    let resp = svc
        .create(uid, None, "k".into(), vec![], future())
        .await
        .unwrap();
    svc.revoke(uid, resp.key.id).await.unwrap();
    let keys = svc.list(uid).await.unwrap();
    assert!(keys.is_empty());
}

#[tokio::test]
async fn authenticate_valid_key() {
    let s = store();
    let uid = create_user(&s).await;
    let svc = ApiKeyService::new(s);
    let resp = svc
        .create(uid, None, "k".into(), vec!["read".into()], future())
        .await
        .unwrap();
    let key = svc.authenticate(&resp.raw_key).await.unwrap();
    assert_eq!(key.user_id, uid);
    assert!(key.last_used_at.is_some());
}

#[tokio::test]
async fn create_rejects_past_expiry() {
    let s = store();
    let uid = create_user(&s).await;
    let svc = ApiKeyService::new(s);
    let past = Utc::now() - chrono::Duration::hours(1);
    let err = svc
        .create(uid, None, "k".into(), vec![], past)
        .await
        .expect_err("past expiry must be rejected");
    assert!(matches!(err, authx_core::error::AuthError::Internal(_)));
}

#[tokio::test]
async fn create_rejects_expiry_beyond_max() {
    let s = store();
    let uid = create_user(&s).await;
    let svc = ApiKeyService::new(s);
    let too_far = Utc::now() + chrono::Duration::days(366);
    let err = svc
        .create(uid, None, "k".into(), vec![], too_far)
        .await
        .expect_err("expiry beyond 365 days must be rejected");
    assert!(matches!(err, authx_core::error::AuthError::Internal(_)));
}

#[tokio::test]
async fn authenticate_expired_key_fails() {
    // Insert a key that is already expired directly via the repository
    // (bypassing the service-layer guard, which prevents creating past-expiry keys).
    use authx_core::{crypto::sha256_hex, models::CreateApiKey};
    use authx_storage::ports::ApiKeyRepository;

    let s = store();
    let uid = create_user(&s).await;

    let raw_key = "deadbeef".repeat(8); // 64-char hex-like string
    let key_hash = sha256_hex(raw_key.as_bytes());
    ApiKeyRepository::create(
        &s,
        CreateApiKey {
            user_id: uid,
            org_id: None,
            key_hash,
            prefix: raw_key[..8].to_owned(),
            name: "expired".into(),
            scopes: vec![],
            expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
        },
    )
    .await
    .unwrap();

    let svc = ApiKeyService::new(s);
    assert!(svc.authenticate(&raw_key).await.is_err());
}
