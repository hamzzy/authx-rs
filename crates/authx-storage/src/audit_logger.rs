use std::sync::Arc;

use authx_core::{
    events::{AuthEvent, EventBus},
    models::CreateAuditLog,
};

use crate::ports::AuditLogRepository;

/// Subscribes to the [`EventBus`] and persists every [`AuthEvent`] as an
/// [`AuditLog`] row via [`AuditLogRepository`].
///
/// Spawn this once at startup with [`AuditLogger::run`] — it drives itself
/// in a detached Tokio task and never needs to be awaited.
///
/// ```rust,ignore
/// let logger = AuditLogger::new(store.clone(), events.clone());
/// logger.run(); // spawns background task
/// ```
pub struct AuditLogger<S> {
    store:  Arc<S>,
    events: EventBus,
}

impl<S> AuditLogger<S>
where
    S: AuditLogRepository + Send + Sync + 'static,
{
    pub fn new(store: S, events: EventBus) -> Self {
        Self { store: Arc::new(store), events }
    }

    /// Spawn a background task that drains the event bus and writes audit rows.
    /// Returns immediately; the task runs until the process exits.
    pub fn run(self) {
        let store  = Arc::clone(&self.store);
        let mut rx = self.events.subscribe();

        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        let entry = event_to_audit(&event);
                        if let Err(e) = store.append(entry).await {
                            tracing::error!(error = %e, "audit log write failed");
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(dropped = n, "audit logger lagged — events dropped");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        tracing::info!("audit event bus closed — logger shutting down");
                        break;
                    }
                }
            }
        });
    }
}

fn event_to_audit(event: &AuthEvent) -> CreateAuditLog {
    match event {
        AuthEvent::UserCreated { user } => CreateAuditLog {
            user_id:       Some(user.id),
            org_id:        None,
            action:        "user.created".into(),
            resource_type: "user".into(),
            resource_id:   Some(user.id.to_string()),
            ip_address:    String::new(),
            metadata:      None,
        },
        AuthEvent::UserUpdated { user } => CreateAuditLog {
            user_id:       Some(user.id),
            org_id:        None,
            action:        "user.updated".into(),
            resource_type: "user".into(),
            resource_id:   Some(user.id.to_string()),
            ip_address:    String::new(),
            metadata:      None,
        },
        AuthEvent::SignIn { user, session } => CreateAuditLog {
            user_id:       Some(user.id),
            org_id:        session.org_id,
            action:        "auth.sign_in".into(),
            resource_type: "session".into(),
            resource_id:   Some(session.id.to_string()),
            ip_address:    session.ip_address.clone(),
            metadata:      None,
        },
        AuthEvent::SignOut { user_id, session_id } => CreateAuditLog {
            user_id:       Some(*user_id),
            org_id:        None,
            action:        "auth.sign_out".into(),
            resource_type: "session".into(),
            resource_id:   Some(session_id.to_string()),
            ip_address:    String::new(),
            metadata:      None,
        },
        AuthEvent::SessionExpired { user_id, session_id } => CreateAuditLog {
            user_id:       Some(*user_id),
            org_id:        None,
            action:        "session.expired".into(),
            resource_type: "session".into(),
            resource_id:   Some(session_id.to_string()),
            ip_address:    String::new(),
            metadata:      None,
        },
        AuthEvent::PasswordChanged { user_id } => CreateAuditLog {
            user_id:       Some(*user_id),
            org_id:        None,
            action:        "auth.password_changed".into(),
            resource_type: "user".into(),
            resource_id:   Some(user_id.to_string()),
            ip_address:    String::new(),
            metadata:      None,
        },
        AuthEvent::EmailVerified { user_id } => CreateAuditLog {
            user_id:       Some(*user_id),
            org_id:        None,
            action:        "auth.email_verified".into(),
            resource_type: "user".into(),
            resource_id:   Some(user_id.to_string()),
            ip_address:    String::new(),
            metadata:      None,
        },
    }
}
