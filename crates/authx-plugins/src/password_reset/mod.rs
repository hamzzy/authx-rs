mod service;

pub use service::{PasswordResetRequest, PasswordResetService};

#[cfg(test)]
mod tests {
    use super::service::{PasswordResetRequest, PasswordResetService};
    use authx_core::{
        error::AuthError,
        events::EventBus,
        models::CreateUser,
    };
    use authx_storage::{memory::MemoryStore, ports::UserRepository};

    fn setup() -> (MemoryStore, EventBus) {
        (MemoryStore::new(), EventBus::new())
    }

    async fn make_user(store: &MemoryStore) -> uuid::Uuid {
        UserRepository::create(store, CreateUser {
            email:    "reset@example.com".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id
    }

    #[tokio::test]
    async fn request_reset_returns_none_for_unknown_email() {
        let (store, events) = setup();
        let svc = PasswordResetService::new(store, events);
        let tok = svc.request_reset("nobody@x.com").await.unwrap();
        assert!(tok.is_none());
    }

    #[tokio::test]
    async fn request_reset_returns_token_for_known_email() {
        let (store, events) = setup();
        make_user(&store).await;
        let svc = PasswordResetService::new(store, events);
        let tok = svc.request_reset("reset@example.com").await.unwrap();
        assert!(tok.is_some());
        assert_eq!(tok.unwrap().len(), 64); // 32 bytes hex
    }

    #[tokio::test]
    async fn reset_password_fails_with_bad_token() {
        let (store, events) = setup();
        let svc = PasswordResetService::new(store, events);
        let err = svc.reset_password(PasswordResetRequest {
            token:        "bad_token".into(),
            new_password: "newpassword123".into(),
        })
        .await
        .unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[tokio::test]
    async fn reset_password_succeeds_with_valid_token() {
        use authx_core::models::{CreateCredential, CredentialKind};
        use authx_core::crypto::hash_password;
        use authx_storage::ports::CredentialRepository;

        let (store, events) = setup();
        let uid = make_user(&store).await;

        // Give the user an initial password.
        let old_hash = hash_password("oldpass123").unwrap();
        CredentialRepository::create(&store, CreateCredential {
            user_id:         uid,
            kind:            CredentialKind::Password,
            credential_hash: old_hash,
            metadata:        None,
        })
        .await
        .unwrap();

        let svc = PasswordResetService::new(store.clone(), events);
        let token = svc
            .request_reset("reset@example.com")
            .await
            .unwrap()
            .unwrap();

        svc.reset_password(PasswordResetRequest {
            token,
            new_password: "newpass456".into(),
        })
        .await
        .unwrap();

        // New credential should allow sign-in with new password.
        let new_hash = CredentialRepository::find_password_hash(&store, uid)
            .await
            .unwrap()
            .unwrap();
        assert!(authx_core::crypto::verify_password(&new_hash, "newpass456").unwrap());
    }

    #[tokio::test]
    async fn reset_password_rejects_same_password() {
        use authx_core::models::{CreateCredential, CredentialKind};
        use authx_core::crypto::hash_password;
        use authx_storage::ports::CredentialRepository;

        let (store, events) = setup();
        let uid = make_user(&store).await;

        let old_hash = hash_password("samepass123").unwrap();
        CredentialRepository::create(&store, CreateCredential {
            user_id:         uid,
            kind:            CredentialKind::Password,
            credential_hash: old_hash,
            metadata:        None,
        })
        .await
        .unwrap();

        let svc = PasswordResetService::new(store.clone(), events);
        let token = svc.request_reset("reset@example.com").await.unwrap().unwrap();

        let err = svc.reset_password(PasswordResetRequest {
            token,
            new_password: "samepass123".into(),
        })
        .await
        .unwrap_err();

        assert!(matches!(err, AuthError::Internal(_)));
    }
}
