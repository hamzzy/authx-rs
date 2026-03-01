---
title: Events & Audit
description: The EventBus and AuditLogger for real-time event streaming and tamper-evident logging.
---

## EventBus

`EventBus` wraps a `tokio::sync::broadcast` channel. Plugins emit typed events; any number of subscribers can listen.

```rust
use authx_core::events::{AuthEvent, EventBus};

let events = EventBus::new();

// Emit (non-blocking — fire and forget)
events.emit(AuthEvent::SignIn { user: user.clone(), session: session.clone() });

// Subscribe
let mut rx = events.subscribe();
tokio::spawn(async move {
    loop {
        match rx.recv().await {
            Ok(event)  => println!("event: {:?}", event),
            Err(_)     => break,
        }
    }
});
```

## Event variants

| Event | Emitted by |
|---|---|
| `UserCreated { user }` | `EmailPasswordService::sign_up`, `AdminService::create_user` |
| `UserUpdated { user }` | Various update paths |
| `SignIn { user, session }` | `EmailPasswordService::sign_in`, `MagicLinkService::verify`, etc. |
| `SignOut { user_id, session_id }` | `sign_out`, `sign_out_all`, `AdminService::revoke_all_sessions` |
| `SessionExpired { user_id, session_id }` | Expiry check |
| `PasswordChanged { user_id }` | `PasswordResetService::reset_password` |
| `EmailVerified { user_id }` | `EmailVerificationService::verify` |
| `OAuthLinked { user_id, provider }` | `OAuthService::callback` |
| `InviteAccepted { membership }` | `OrgService::accept_invite` |

## AuditLogger

`AuditLogger` subscribes to the `EventBus` and persists every event as an `AuditLog` row — asynchronously, without blocking the request path.

```rust
use authx_storage::AuditLogger;

// Start the background logger — call once at app startup
AuditLogger::new(store.clone(), events.clone()).run();
```

Audit log entries include `user_id`, `org_id`, `action`, `resource_type`, `resource_id`, `ip_address`, and `metadata`.

## Querying audit logs

```rust
use authx_storage::ports::AuditLogRepository;

let logs = AuditLogRepository::find_by_user(&store, user_id, 50).await?;
let logs = AuditLogRepository::find_by_org(&store, org_id, 50).await?;
```

## Custom subscribers

Wire in your own logic — send to Slack, stream to Kafka, trigger webhooks:

```rust
let mut rx = events.subscribe();
tokio::spawn(async move {
    while let Ok(event) = rx.recv().await {
        if let AuthEvent::SignIn { ref user, .. } = event {
            notify_slack(&format!("User {} signed in", user.email)).await;
        }
    }
});
```
