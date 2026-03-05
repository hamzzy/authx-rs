use std::time::Duration;

use authx_core::{brute_force::LockoutConfig, error::AuthError, events::EventBus};
use authx_storage::memory::MemoryStore;

use super::service::{EmailPasswordService, SignInRequest, SignUpRequest};

fn make_service() -> EmailPasswordService<MemoryStore> {
    EmailPasswordService::new(MemoryStore::new(), EventBus::new(), 8, 3600)
}

#[tokio::test]
async fn sign_up_creates_user() {
    let svc = make_service();
    let user = svc
        .sign_up(SignUpRequest {
            email: "alice@example.com".into(),
            password: "Hunter42!".into(),
            ip: "127.0.0.1".into(),
        })
        .await
        .expect("sign_up failed");

    assert_eq!(user.email, "alice@example.com");
}

#[tokio::test]
async fn sign_up_rejects_duplicate_email() {
    let svc = make_service();
    let req = || SignUpRequest {
        email: "dup@example.com".into(),
        password: "Hunter42!".into(),
        ip: "127.0.0.1".into(),
    };

    svc.sign_up(req()).await.expect("first sign_up failed");
    let err = svc
        .sign_up(req())
        .await
        .expect_err("expected duplicate error");
    assert!(matches!(err, AuthError::EmailTaken), "got: {err:?}");
}

#[tokio::test]
async fn sign_up_rejects_short_password() {
    let svc = make_service();
    let err = svc
        .sign_up(SignUpRequest {
            email: "short@example.com".into(),
            password: "abc".into(),
            ip: "127.0.0.1".into(),
        })
        .await
        .expect_err("expected password error");

    assert!(matches!(err, AuthError::WeakPassword), "got: {err:?}");
}

#[tokio::test]
async fn sign_up_rejects_invalid_email() {
    let svc = make_service();
    let err = svc
        .sign_up(SignUpRequest {
            email: "not-an-email".into(),
            password: "Hunter42!".into(),
            ip: "127.0.0.1".into(),
        })
        .await
        .expect_err("expected email validation error");

    assert!(matches!(err, AuthError::Internal(_)), "got: {err:?}");
}

#[tokio::test]
async fn sign_in_returns_token_and_session() {
    let svc = make_service();
    svc.sign_up(SignUpRequest {
        email: "bob@example.com".into(),
        password: "Correct-Horse1!".into(),
        ip: "10.0.0.1".into(),
    })
    .await
    .unwrap();

    let resp = svc
        .sign_in(SignInRequest {
            email: "bob@example.com".into(),
            password: "Correct-Horse1!".into(),
            ip: "10.0.0.2".into(),
            remember_me: false,
        })
        .await
        .expect("sign_in failed");

    assert_eq!(resp.user.email, "bob@example.com");
    assert!(!resp.token.is_empty());
    assert_eq!(resp.session.user_id, resp.user.id);
}

#[tokio::test]
async fn remember_me_uses_longer_session_ttl() {
    let svc = EmailPasswordService::new(MemoryStore::new(), EventBus::new(), 8, 3600)
        .with_remember_me_ttl(86_400);
    svc.sign_up(SignUpRequest {
        email: "remember@example.com".into(),
        password: "Correct-Horse1!".into(),
        ip: "127.0.0.1".into(),
    })
    .await
    .unwrap();

    let normal = svc
        .sign_in(SignInRequest {
            email: "remember@example.com".into(),
            password: "Correct-Horse1!".into(),
            ip: "127.0.0.1".into(),
            remember_me: false,
        })
        .await
        .unwrap();
    let remembered = svc
        .sign_in(SignInRequest {
            email: "remember@example.com".into(),
            password: "Correct-Horse1!".into(),
            ip: "127.0.0.1".into(),
            remember_me: true,
        })
        .await
        .unwrap();

    assert!(remembered.session.expires_at > normal.session.expires_at);
    assert_eq!(normal.session_ttl_secs, 3600);
    assert_eq!(remembered.session_ttl_secs, 86_400);
}

#[tokio::test]
async fn sign_in_rejects_wrong_password() {
    let svc = make_service();
    svc.sign_up(SignUpRequest {
        email: "carol@example.com".into(),
        password: "Correct-Horse1!".into(),
        ip: "127.0.0.1".into(),
    })
    .await
    .unwrap();

    let err = svc
        .sign_in(SignInRequest {
            email: "carol@example.com".into(),
            password: "wrong-password".into(),
            ip: "127.0.0.1".into(),
            remember_me: false,
        })
        .await
        .expect_err("expected auth failure");

    assert!(matches!(err, AuthError::InvalidCredentials), "got: {err:?}");
}

#[tokio::test]
async fn sign_in_rejects_unknown_email() {
    let svc = make_service();
    let err = svc
        .sign_in(SignInRequest {
            email: "nobody@example.com".into(),
            password: "anything".into(),
            ip: "127.0.0.1".into(),
            remember_me: false,
        })
        .await
        .expect_err("expected not found");

    assert!(matches!(err, AuthError::InvalidCredentials), "got: {err:?}");
}

#[tokio::test]
async fn sign_out_invalidates_session() {
    let svc = make_service();
    svc.sign_up(SignUpRequest {
        email: "dave@example.com".into(),
        password: "Passw0rd!".into(),
        ip: "127.0.0.1".into(),
    })
    .await
    .unwrap();

    let resp = svc
        .sign_in(SignInRequest {
            email: "dave@example.com".into(),
            password: "Passw0rd!".into(),
            ip: "127.0.0.1".into(),
            remember_me: false,
        })
        .await
        .unwrap();

    svc.sign_out(resp.session.id)
        .await
        .expect("sign_out failed");

    let sessions = svc.list_sessions(resp.user.id).await.unwrap();
    assert!(
        sessions.iter().all(|s| s.id != resp.session.id),
        "invalidated session still listed"
    );
}

#[tokio::test]
async fn sign_out_all_clears_every_session() {
    let svc = make_service();
    svc.sign_up(SignUpRequest {
        email: "eve@example.com".into(),
        password: "Passw0rd!".into(),
        ip: "127.0.0.1".into(),
    })
    .await
    .unwrap();

    let resp1 = svc
        .sign_in(SignInRequest {
            email: "eve@example.com".into(),
            password: "Passw0rd!".into(),
            ip: "1.1.1.1".into(),
            remember_me: false,
        })
        .await
        .unwrap();

    let _ = svc
        .sign_in(SignInRequest {
            email: "eve@example.com".into(),
            password: "Passw0rd!".into(),
            ip: "2.2.2.2".into(),
            remember_me: false,
        })
        .await
        .unwrap();

    svc.sign_out_all(resp1.user.id)
        .await
        .expect("sign_out_all failed");

    let sessions = svc.list_sessions(resp1.user.id).await.unwrap();
    assert!(
        sessions.is_empty(),
        "expected no sessions after sign_out_all"
    );
}

#[tokio::test]
async fn list_sessions_returns_all_active() {
    let svc = make_service();
    svc.sign_up(SignUpRequest {
        email: "frank@example.com".into(),
        password: "Passw0rd!".into(),
        ip: "127.0.0.1".into(),
    })
    .await
    .unwrap();

    let login = |ip: &'static str| {
        let svc = &svc;
        async move {
            svc.sign_in(SignInRequest {
                email: "frank@example.com".into(),
                password: "Passw0rd!".into(),
                ip: ip.into(),
                remember_me: false,
            })
            .await
            .unwrap()
        }
    };

    let r1 = login("1.2.3.4").await;
    let r2 = login("5.6.7.8").await;
    let r3 = login("9.10.11.12").await;

    let sessions = svc.list_sessions(r1.user.id).await.unwrap();
    let ids: Vec<_> = sessions.iter().map(|s| s.id).collect();

    assert!(ids.contains(&r1.session.id));
    assert!(ids.contains(&r2.session.id));
    assert!(ids.contains(&r3.session.id));
}

// ── Brute-force lockout ───────────────────────────────────────────────────────

fn make_service_with_lockout(max_failures: u32) -> EmailPasswordService<MemoryStore> {
    let cfg = LockoutConfig::new(max_failures, Duration::from_secs(60));
    EmailPasswordService::new(MemoryStore::new(), EventBus::new(), 8, 3600).with_lockout(cfg)
}

#[tokio::test]
async fn lockout_triggers_after_max_failures() {
    let svc = make_service_with_lockout(3);

    svc.sign_up(SignUpRequest {
        email: "grace@example.com".into(),
        password: "Correct-Pass1!".into(),
        ip: "127.0.0.1".into(),
    })
    .await
    .unwrap();

    let bad_attempt = || SignInRequest {
        email: "grace@example.com".into(),
        password: "wrong".into(),
        ip: "127.0.0.1".into(),
        remember_me: false,
    };

    // Three failures should trigger lockout.
    for _ in 0..3 {
        let _ = svc.sign_in(bad_attempt()).await;
    }

    let err = svc
        .sign_in(bad_attempt())
        .await
        .expect_err("expected lockout");
    assert!(matches!(err, AuthError::AccountLocked), "got: {err:?}");
}

#[tokio::test]
async fn lockout_clears_on_success() {
    let svc = make_service_with_lockout(3);

    svc.sign_up(SignUpRequest {
        email: "henry@example.com".into(),
        password: "Correct-Pass1!".into(),
        ip: "127.0.0.1".into(),
    })
    .await
    .unwrap();

    // Two failures — not yet locked.
    for _ in 0..2 {
        let _ = svc
            .sign_in(SignInRequest {
                email: "henry@example.com".into(),
                password: "wrong".into(),
                ip: "127.0.0.1".into(),
                remember_me: false,
            })
            .await;
    }

    // Successful sign-in resets counter.
    svc.sign_in(SignInRequest {
        email: "henry@example.com".into(),
        password: "Correct-Pass1!".into(),
        ip: "127.0.0.1".into(),
        remember_me: false,
    })
    .await
    .expect("sign-in should succeed after counter reset");

    // Fail twice more — should NOT be locked (counter was cleared).
    for _ in 0..2 {
        let _ = svc
            .sign_in(SignInRequest {
                email: "henry@example.com".into(),
                password: "wrong".into(),
                ip: "127.0.0.1".into(),
                remember_me: false,
            })
            .await;
    }

    // Still not locked — only 2 failures since last success.
    let result = svc
        .sign_in(SignInRequest {
            email: "henry@example.com".into(),
            password: "Correct-Pass1!".into(),
            ip: "127.0.0.1".into(),
            remember_me: false,
        })
        .await;
    assert!(result.is_ok(), "should not be locked: {result:?}");
}

#[tokio::test]
async fn no_lockout_without_config() {
    // Default service (no .with_lockout) — error is always InvalidCredentials,
    // never AccountLocked. Keep iteration count low to avoid Argon2 slowness.
    let svc = make_service();

    svc.sign_up(SignUpRequest {
        email: "ivan@example.com".into(),
        password: "Correct-Pass1!".into(),
        ip: "127.0.0.1".into(),
    })
    .await
    .unwrap();

    for _ in 0..3 {
        let err = svc
            .sign_in(SignInRequest {
                email: "ivan@example.com".into(),
                password: "wrong".into(),
                ip: "127.0.0.1".into(),
                remember_me: false,
            })
            .await
            .expect_err("expected error");

        assert!(matches!(err, AuthError::InvalidCredentials), "got: {err:?}");
    }
}
