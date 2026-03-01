mod service;

pub use service::{MagicLinkService, MagicLinkVerifyResponse};

#[cfg(test)]
mod tests {
    use super::service::MagicLinkService;
    use authx_core::{events::EventBus, models::CreateUser};
    use authx_storage::{memory::MemoryStore, ports::UserRepository};

    fn setup() -> (MemoryStore, EventBus) {
        (MemoryStore::new(), EventBus::new())
    }

    async fn make_user(store: &MemoryStore, email: &str) -> uuid::Uuid {
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
    async fn request_link_returns_none_for_unknown_email() {
        let (store, events) = setup();
        let svc = MagicLinkService::new(store, events, 3600);
        assert!(svc.request_link("ghost@x.com").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn request_link_returns_token_for_known_email() {
        let (store, events) = setup();
        make_user(&store, "magic@example.com").await;
        let svc = MagicLinkService::new(store, events, 3600);
        let tok = svc.request_link("magic@example.com").await.unwrap();
        assert!(tok.is_some());
        assert_eq!(tok.unwrap().len(), 64);
    }

    #[tokio::test]
    async fn verify_with_bad_token_fails() {
        let (store, events) = setup();
        let svc = MagicLinkService::new(store, events, 3600);
        let err = svc.verify("notavalidtoken", "127.0.0.1").await.unwrap_err();
        assert!(matches!(err, authx_core::error::AuthError::InvalidToken));
    }

    #[tokio::test]
    async fn verify_creates_session_and_returns_token() {
        let (store, events) = setup();
        make_user(&store, "magic@example.com").await;
        let svc = MagicLinkService::new(store, events, 3600);

        let raw_token = svc
            .request_link("magic@example.com")
            .await
            .unwrap()
            .unwrap();

        let resp = svc.verify(&raw_token, "10.0.0.1").await.unwrap();
        assert_eq!(resp.user.email, "magic@example.com");
        assert_eq!(resp.session.ip_address, "10.0.0.1");
        assert_eq!(resp.token.len(), 64);
    }

    #[tokio::test]
    async fn verify_is_single_use() {
        let (store, events) = setup();
        make_user(&store, "magic@example.com").await;
        let svc = MagicLinkService::new(store, events, 3600);

        let raw_token = svc
            .request_link("magic@example.com")
            .await
            .unwrap()
            .unwrap();

        svc.verify(&raw_token, "127.0.0.1").await.unwrap();

        let err = svc.verify(&raw_token, "127.0.0.1").await.unwrap_err();
        assert!(matches!(err, authx_core::error::AuthError::InvalidToken));
    }
}
