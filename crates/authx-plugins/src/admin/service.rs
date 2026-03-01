use chrono::Utc;
use tracing::instrument;
use uuid::Uuid;

use authx_core::{
    crypto::sha256_hex,
    error::{AuthError, Result},
    events::{AuthEvent, EventBus},
    models::{CreateSession, Session, UpdateUser, User},
};
use authx_storage::ports::{AuditLogRepository, SessionRepository, UserRepository};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanStatus {
    Banned,
    Active,
}

/// Admin service — privileged operations.
///
/// Callers are responsible for verifying that the *acting* identity has admin
/// privileges before calling any method (use `RequireRole::check` or
/// `AuthzEngine::enforce`).
pub struct AdminService<S> {
    storage:          S,
    events:           EventBus,
    session_ttl_secs: i64,
}

impl<S> AdminService<S>
where
    S: UserRepository + SessionRepository + AuditLogRepository + Clone + Send + Sync + 'static,
{
    pub fn new(storage: S, events: EventBus, session_ttl_secs: i64) -> Self {
        Self { storage, events, session_ttl_secs }
    }

    /// List all users (paginated by `offset` + `limit`).
    #[instrument(skip(self))]
    pub async fn list_users(&self, offset: u32, limit: u32) -> Result<Vec<User>> {
        // MemoryStore / Postgres adapters expose find_by_email but no paginated list.
        // We implement this at the admin layer using find_by_id as a stub —
        // production implementations should add a paginated `list_users` repo method.
        // For now, delegate to the actor calling code to issue their own list query.
        let _ = (offset, limit);
        tracing::warn!("AdminService::list_users: implement a paginated UserRepository::list method for production use");
        Ok(vec![])
    }

    /// Look up any user by id.
    #[instrument(skip(self), fields(target = %user_id))]
    pub async fn get_user(&self, user_id: Uuid) -> Result<User> {
        UserRepository::find_by_id(&self.storage, user_id)
            .await?
            .ok_or(AuthError::UserNotFound)
    }

    /// Soft-ban a user by marking metadata `{"banned": true}`.
    ///
    /// All existing sessions are revoked immediately. New sign-in attempts
    /// must check `metadata["banned"]` before issuing sessions — this is
    /// enforced by the email-password service if you add that check.
    #[instrument(skip(self), fields(target = %user_id, acting_admin = %admin_id))]
    pub async fn ban_user(&self, admin_id: Uuid, user_id: Uuid, reason: &str) -> Result<()> {
        // Update metadata to mark as banned.
        UserRepository::update(
            &self.storage,
            user_id,
            UpdateUser {
                metadata: Some(serde_json::json!({ "banned": true, "ban_reason": reason })),
                ..Default::default()
            },
        )
        .await?;

        // Revoke all active sessions.
        SessionRepository::invalidate_all_for_user(&self.storage, user_id).await?;

        AuditLogRepository::append(
            &self.storage,
            authx_core::models::CreateAuditLog {
                user_id:       Some(admin_id),
                org_id:        None,
                action:        "admin.ban_user".into(),
                resource_type: "user".into(),
                resource_id:   Some(user_id.to_string()),
                ip_address:    String::new(),
                metadata:      Some(serde_json::json!({ "reason": reason })),
            },
        )
        .await?;

        tracing::info!(admin = %admin_id, target = %user_id, reason, "user banned");
        Ok(())
    }

    /// Lift a ban.
    #[instrument(skip(self), fields(target = %user_id, acting_admin = %admin_id))]
    pub async fn unban_user(&self, admin_id: Uuid, user_id: Uuid) -> Result<()> {
        UserRepository::update(
            &self.storage,
            user_id,
            UpdateUser {
                metadata: Some(serde_json::json!({ "banned": false })),
                ..Default::default()
            },
        )
        .await?;

        AuditLogRepository::append(
            &self.storage,
            authx_core::models::CreateAuditLog {
                user_id:       Some(admin_id),
                org_id:        None,
                action:        "admin.unban_user".into(),
                resource_type: "user".into(),
                resource_id:   Some(user_id.to_string()),
                ip_address:    String::new(),
                metadata:      None,
            },
        )
        .await?;

        tracing::info!(admin = %admin_id, target = %user_id, "user unbanned");
        Ok(())
    }

    /// Check whether a user is currently banned.
    pub async fn ban_status(&self, user_id: Uuid) -> Result<BanStatus> {
        let user = UserRepository::find_by_id(&self.storage, user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let banned = user.metadata.get("banned").and_then(|v| v.as_bool()).unwrap_or(false);
        Ok(if banned { BanStatus::Banned } else { BanStatus::Active })
    }

    /// Create an impersonation session for `target_user_id`.
    ///
    /// The session `ip_address` is tagged `"impersonation:<admin_id>"` so audit
    /// queries can distinguish impersonated from real sessions.
    #[instrument(skip(self), fields(target = %target_id, acting_admin = %admin_id))]
    pub async fn impersonate(
        &self,
        admin_id:  Uuid,
        target_id: Uuid,
        admin_ip:  &str,
    ) -> Result<(Session, String)> {
        let raw: [u8; 32] = rand::thread_rng().gen();
        let raw_token  = hex::encode(raw);
        let token_hash = sha256_hex(raw_token.as_bytes());

        let session = SessionRepository::create(
            &self.storage,
            CreateSession {
                user_id:     target_id,
                token_hash,
                device_info: serde_json::json!({ "impersonated_by": admin_id }),
                ip_address:  format!("impersonation:{admin_id}@{admin_ip}"),
                org_id:      None,
                expires_at:  Utc::now() + chrono::Duration::seconds(self.session_ttl_secs),
            },
        )
        .await?;

        AuditLogRepository::append(
            &self.storage,
            authx_core::models::CreateAuditLog {
                user_id:       Some(admin_id),
                org_id:        None,
                action:        "admin.impersonate".into(),
                resource_type: "session".into(),
                resource_id:   Some(session.id.to_string()),
                ip_address:    admin_ip.to_owned(),
                metadata:      Some(serde_json::json!({ "target_user_id": target_id })),
            },
        )
        .await?;

        tracing::info!(admin = %admin_id, target = %target_id, session_id = %session.id, "impersonation session created");
        Ok((session, raw_token))
    }

    /// List all active sessions for any user (admin view).
    #[instrument(skip(self), fields(target = %user_id))]
    pub async fn list_sessions(&self, user_id: Uuid) -> Result<Vec<Session>> {
        SessionRepository::find_by_user(&self.storage, user_id).await
    }

    /// Revoke all sessions for any user (admin-forced sign-out).
    #[instrument(skip(self), fields(target = %user_id, acting_admin = %admin_id))]
    pub async fn revoke_all_sessions(&self, admin_id: Uuid, user_id: Uuid) -> Result<()> {
        SessionRepository::invalidate_all_for_user(&self.storage, user_id).await?;
        self.events.emit(AuthEvent::SignOut {
            user_id,
            session_id: Uuid::nil(), // admin-forced; no single session_id
        });
        tracing::info!(admin = %admin_id, target = %user_id, "all sessions revoked by admin");
        Ok(())
    }
}

use rand::Rng;
