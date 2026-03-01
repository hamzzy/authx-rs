use super::*;
use authx_core::events::EventBus;
use authx_storage::memory::MemoryStore;
use uuid::Uuid;

fn svc_and_store() -> (OrgService<MemoryStore>, MemoryStore) {
    let store = MemoryStore::new();
    let svc   = OrgService::new(store.clone(), EventBus::new());
    (svc, store)
}

#[tokio::test]
async fn create_org_adds_owner() {
    let (s, _) = svc_and_store();
    let owner  = Uuid::new_v4();
    let (org, membership) = s.create(owner, "ACME".into(), "acme".into(), None).await.unwrap();
    assert_eq!(org.slug, "acme");
    assert_eq!(membership.user_id, owner);
    assert_eq!(membership.role.name, "owner");
}

#[tokio::test]
async fn invite_and_accept() {
    let (s, _) = svc_and_store();
    let owner  = Uuid::new_v4();
    let (org, member) = s.create(owner, "Acme".into(), "acme2".into(), None).await.unwrap();
    let invitee        = Uuid::new_v4();
    let details        = s.invite_member(org.id, "invitee@example.com".into(), member.role.id, owner).await.unwrap();
    let membership     = s.accept_invite(&details.raw_token, invitee).await.unwrap();
    assert_eq!(membership.user_id, invitee);
    assert_eq!(membership.org_id, org.id);
}

#[tokio::test]
async fn accept_invite_twice_fails() {
    let (s, _) = svc_and_store();
    let owner  = Uuid::new_v4();
    let (org, member) = s.create(owner, "Acme".into(), "acme3".into(), None).await.unwrap();
    let details = s.invite_member(org.id, "a@b.com".into(), member.role.id, owner).await.unwrap();
    s.accept_invite(&details.raw_token, Uuid::new_v4()).await.unwrap();
    assert!(s.accept_invite(&details.raw_token, Uuid::new_v4()).await.is_err());
}

#[tokio::test]
async fn switch_org_updates_session() {
    use authx_core::models::CreateSession;
    use authx_storage::ports::SessionRepository;
    let (s, store) = svc_and_store();
    let session = SessionRepository::create(
        &store,
        CreateSession {
            user_id:     Uuid::new_v4(),
            token_hash:  "hash".into(),
            device_info: serde_json::Value::Null,
            ip_address:  "127.0.0.1".into(),
            org_id:      None,
            expires_at:  chrono::Utc::now() + chrono::Duration::hours(1),
        },
    )
    .await
    .unwrap();
    let org_id  = Uuid::new_v4();
    let updated = s.switch_org(session.id, Some(org_id)).await.unwrap();
    assert_eq!(updated.org_id, Some(org_id));
}

#[tokio::test]
async fn remove_member_works() {
    let (s, _) = svc_and_store();
    let owner  = Uuid::new_v4();
    let (org, _) = s.create(owner, "Acme".into(), "acme4".into(), None).await.unwrap();
    s.remove_member(org.id, owner, owner).await.unwrap();
    let members = s.list_members(org.id).await.unwrap();
    assert!(members.iter().all(|m| m.user_id != owner));
}

#[tokio::test]
async fn duplicate_slug_rejected() {
    let (s, _) = svc_and_store();
    s.create(Uuid::new_v4(), "Acme".into(), "unique".into(), None).await.unwrap();
    assert!(s.create(Uuid::new_v4(), "Acme2".into(), "unique".into(), None).await.is_err());
}
