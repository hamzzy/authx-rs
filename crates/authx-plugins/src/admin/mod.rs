mod service;

pub use service::{AdminService, BanStatus};

#[cfg(test)]
mod tests {
    use super::service::{AdminService, BanStatus};
    use authx_core::{events::EventBus, models::CreateUser};
    use authx_storage::{memory::MemoryStore, ports::UserRepository};
    use uuid::Uuid;

    fn setup() -> (MemoryStore, EventBus) {
        (MemoryStore::new(), EventBus::new())
    }

    async fn make_user(store: &MemoryStore, email: &str) -> Uuid {
        UserRepository::create(
            store,
            CreateUser {
                email: email.into(),
                username: None,
                metadata: None,
            },
        )
        .await
        .unwrap()
        .id
    }

    #[tokio::test]
    async fn ban_and_check_status() {
        let (store, events) = setup();
        let admin_id = make_user(&store, "admin@x.com").await;
        let user_id = make_user(&store, "user@x.com").await;
        let svc = AdminService::new(store.clone(), events, 3600);
        svc.ban_user(admin_id, user_id, "test ban").await.unwrap();
        assert_eq!(svc.ban_status(user_id).await.unwrap(), BanStatus::Banned);
    }

    #[tokio::test]
    async fn unban_restores_active_status() {
        let (store, events) = setup();
        let admin_id = make_user(&store, "admin@x.com").await;
        let user_id = make_user(&store, "user@x.com").await;
        let svc = AdminService::new(store.clone(), events, 3600);
        svc.ban_user(admin_id, user_id, "temp ban").await.unwrap();
        svc.unban_user(admin_id, user_id).await.unwrap();
        assert_eq!(svc.ban_status(user_id).await.unwrap(), BanStatus::Active);
    }

    #[tokio::test]
    async fn ban_revokes_all_sessions() {
        use authx_core::models::CreateSession;
        use authx_storage::ports::SessionRepository;
        use chrono::Utc;

        let (store, events) = setup();
        let admin_id = make_user(&store, "admin@x.com").await;
        let user_id = make_user(&store, "user@x.com").await;

        SessionRepository::create(
            &store,
            CreateSession {
                user_id,
                token_hash: "abc123".into(),
                device_info: serde_json::Value::Null,
                ip_address: "127.0.0.1".into(),
                org_id: None,
                expires_at: Utc::now() + chrono::Duration::hours(1),
            },
        )
        .await
        .unwrap();

        let svc = AdminService::new(store.clone(), events, 3600);
        svc.ban_user(admin_id, user_id, "session test")
            .await
            .unwrap();
        let sessions = SessionRepository::find_by_user(&store, user_id)
            .await
            .unwrap();
        assert!(sessions.is_empty());
    }

    #[tokio::test]
    async fn impersonate_creates_tagged_session() {
        let (store, events) = setup();
        let admin_id = make_user(&store, "admin@x.com").await;
        let target_id = make_user(&store, "target@x.com").await;
        let svc = AdminService::new(store.clone(), events, 3600);
        let (session, token) = svc
            .impersonate(admin_id, target_id, "10.0.0.1")
            .await
            .unwrap();
        assert_eq!(session.user_id, target_id);
        assert!(session.ip_address.contains("impersonation"));
        assert_eq!(token.len(), 64);
    }

    #[tokio::test]
    async fn get_user_returns_user() {
        let (store, events) = setup();
        let user_id = make_user(&store, "getme@x.com").await;
        let svc = AdminService::new(store.clone(), events, 3600);
        let user = svc.get_user(user_id).await.unwrap();
        assert_eq!(user.email, "getme@x.com");
    }

    #[tokio::test]
    async fn get_user_fails_for_unknown() {
        let (store, events) = setup();
        let svc = AdminService::new(store, events, 3600);
        assert!(svc.get_user(Uuid::new_v4()).await.is_err());
    }

    #[tokio::test]
    async fn list_users_paginated() {
        let (store, events) = setup();
        for i in 0..5 {
            make_user(&store, &format!("u{}@x.com", i)).await;
        }
        let svc = AdminService::new(store.clone(), events, 3600);
        let page = svc.list_users(2, 2).await.unwrap();
        assert_eq!(page.len(), 2);
    }

    #[tokio::test]
    async fn create_user_admin() {
        let (store, events) = setup();
        let admin_id = make_user(&store, "admin@x.com").await;
        let svc = AdminService::new(store.clone(), events, 3600);
        let user = svc.create_user(admin_id, "new@x.com".into()).await.unwrap();
        assert_eq!(user.email, "new@x.com");
    }
}
