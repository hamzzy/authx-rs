mod service;

pub use service::{TotpService, TotpSetup, TotpVerifyRequest};

#[cfg(test)]
mod tests {
    use super::service::{TotpService, TotpVerifyRequest};
    use authx_storage::memory::MemoryStore;
    use authx_core::models::CreateUser;
    use authx_storage::ports::UserRepository;

    fn store() -> MemoryStore { MemoryStore::new() }

    async fn make_user(store: &MemoryStore) -> uuid::Uuid {
        UserRepository::create(store, CreateUser {
            email:    "totp@example.com".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id
    }

    #[tokio::test]
    async fn begin_setup_returns_secret_and_uri() {
        let store = store();
        let svc   = TotpService::new(store.clone(), "TestApp");
        let uid   = make_user(&store).await;

        let setup = svc.begin_setup(uid).await.unwrap();
        assert!(!setup.secret_base32.is_empty());
        assert!(setup.otpauth_uri.starts_with("otpauth://totp/"));
        assert_eq!(setup.backup_codes.len(), 8);
    }

    #[tokio::test]
    async fn begin_setup_fails_for_unknown_user() {
        let svc = TotpService::new(store(), "TestApp");
        let err = svc.begin_setup(uuid::Uuid::new_v4()).await.unwrap_err();
        assert!(matches!(err, authx_core::error::AuthError::UserNotFound));
    }

    #[tokio::test]
    async fn is_enabled_false_before_setup() {
        let store = store();
        let svc   = TotpService::new(store.clone(), "TestApp");
        let uid   = make_user(&store).await;
        assert!(!svc.is_enabled(uid).await.unwrap());
    }

    #[tokio::test]
    async fn verify_fails_with_bad_code_when_not_enrolled() {
        let store = store();
        let svc   = TotpService::new(store.clone(), "TestApp");
        let uid   = make_user(&store).await;

        let err = svc.verify(TotpVerifyRequest { user_id: uid, code: "000000".into() }).await.unwrap_err();
        assert!(matches!(err, authx_core::error::AuthError::InvalidToken));
    }

    #[tokio::test]
    async fn backup_code_accepted_after_enroll() {
        use authx_core::models::{CreateCredential, CredentialKind};
        use authx_storage::ports::CredentialRepository;
        use authx_core::crypto::sha256_hex;

        let store = store();
        let svc   = TotpService::new(store.clone(), "TestApp");
        let uid   = make_user(&store).await;

        let setup = svc.begin_setup(uid).await.unwrap();
        let raw_code = setup.backup_codes[0].clone();
        let hash     = sha256_hex(raw_code.as_bytes());

        // Persist the credential with hashed backup codes directly.
        CredentialRepository::create(&store, CreateCredential {
            user_id:         uid,
            kind:            CredentialKind::Passkey,
            credential_hash: setup.secret_base32.clone(),
            metadata:        Some(serde_json::json!({ "backup_codes": [hash] })),
        })
        .await
        .unwrap();

        svc.verify(TotpVerifyRequest { user_id: uid, code: raw_code })
            .await
            .unwrap();
    }
}
