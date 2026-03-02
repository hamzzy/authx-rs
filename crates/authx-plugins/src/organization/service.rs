use chrono::Utc;
use tracing::instrument;
use uuid::Uuid;

use authx_core::{
    crypto::sha256_hex,
    error::{AuthError, Result},
    events::{AuthEvent, EventBus},
    models::{CreateInvite, CreateOrg, Invite, Membership, Organization, Role},
    validation::validate_slug,
};
use authx_storage::ports::{
    AuditLogRepository, InviteRepository, OrgRepository, SessionRepository,
};

/// Returned by `invite_member`. Caller sends the raw token in the invite email.
#[derive(Debug)]
pub struct InviteDetails {
    pub invite: Invite,
    pub raw_token: String,
}

/// High-level org management service.
///
/// Wraps [`OrgRepository`] + [`InviteRepository`] + [`AuditLogRepository`] with
/// business logic for creating orgs, managing members, and the invite flow.
pub struct OrgService<S> {
    storage: S,
    events: EventBus,
}

impl<S> OrgService<S>
where
    S: OrgRepository
        + InviteRepository
        + SessionRepository
        + AuditLogRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    pub fn new(storage: S, events: EventBus) -> Self {
        Self { storage, events }
    }

    /// Create a new org with an initial "owner" role.
    /// The `owner_id` is added as a member with that role.
    #[instrument(skip(self), fields(owner_id = %owner_id, slug = %slug))]
    pub async fn create(
        &self,
        owner_id: Uuid,
        name: String,
        slug: String,
        metadata: Option<serde_json::Value>,
    ) -> Result<(Organization, Membership)> {
        validate_slug(&slug)?;
        let org = OrgRepository::create(
            &self.storage,
            CreateOrg {
                name,
                slug: slug.clone(),
                metadata,
            },
        )
        .await?;

        let role =
            OrgRepository::create_role(&self.storage, org.id, "owner".into(), vec!["*".into()])
                .await?;

        let membership =
            OrgRepository::add_member(&self.storage, org.id, owner_id, role.id).await?;

        tracing::info!(org_id = %org.id, owner_id = %owner_id, slug = %slug, "org created");
        Ok((org, membership))
    }

    pub async fn get(&self, org_id: Uuid) -> Result<Organization> {
        OrgRepository::find_by_id(&self.storage, org_id)
            .await?
            .ok_or(AuthError::Storage(
                authx_core::error::StorageError::NotFound,
            ))
    }

    pub async fn list_members(&self, org_id: Uuid) -> Result<Vec<Membership>> {
        OrgRepository::get_members(&self.storage, org_id).await
    }

    pub async fn create_role(
        &self,
        org_id: Uuid,
        name: String,
        permissions: Vec<String>,
    ) -> Result<Role> {
        let role = OrgRepository::create_role(&self.storage, org_id, name, permissions).await?;
        tracing::info!(org_id = %org_id, role_id = %role.id, "role created");
        Ok(role)
    }

    pub async fn set_member_role(
        &self,
        org_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
    ) -> Result<Membership> {
        let m = OrgRepository::update_member_role(&self.storage, org_id, user_id, role_id).await?;
        tracing::info!(org_id = %org_id, user_id = %user_id, role_id = %role_id, "member role updated");
        Ok(m)
    }

    #[instrument(skip(self), fields(org_id = %org_id, user_id = %user_id))]
    pub async fn remove_member(&self, org_id: Uuid, user_id: Uuid, actor_id: Uuid) -> Result<()> {
        OrgRepository::remove_member(&self.storage, org_id, user_id).await?;
        use authx_core::models::CreateAuditLog;
        AuditLogRepository::append(
            &self.storage,
            CreateAuditLog {
                user_id: Some(actor_id),
                org_id: Some(org_id),
                action: "org.remove_member".into(),
                resource_type: "membership".into(),
                resource_id: Some(user_id.to_string()),
                ip_address: None,
                metadata: None,
            },
        )
        .await?;
        tracing::info!(org_id = %org_id, user_id = %user_id, actor_id = %actor_id, "member removed");
        Ok(())
    }

    /// Create an org invite. Returns the `Invite` row and the raw token.
    /// The caller is responsible for emailing the raw token to the invitee.
    #[instrument(skip(self), fields(org_id = %org_id, email = %email))]
    pub async fn invite_member(
        &self,
        org_id: Uuid,
        email: String,
        role_id: Uuid,
        _actor_id: Uuid,
    ) -> Result<InviteDetails> {
        let raw: [u8; 32] = rand::Rng::gen(&mut rand::thread_rng());
        let raw_str = hex::encode(raw);
        let token_hash = sha256_hex(raw_str.as_bytes());

        let invite = InviteRepository::create(
            &self.storage,
            CreateInvite {
                org_id,
                email,
                role_id,
                token_hash,
                expires_at: Utc::now() + chrono::Duration::hours(48),
            },
        )
        .await?;

        tracing::info!(org_id = %org_id, invite_id = %invite.id, "invite created");
        Ok(InviteDetails {
            invite,
            raw_token: raw_str,
        })
    }

    /// Accept an invite. Looks up the invite by raw token, verifies it hasn't
    /// expired or been accepted, marks it accepted, then adds the user as a member.
    #[instrument(skip(self, raw_token), fields(user_id = %user_id))]
    pub async fn accept_invite(&self, raw_token: &str, user_id: Uuid) -> Result<Membership> {
        let token_hash = sha256_hex(raw_token.as_bytes());
        let invite = InviteRepository::find_by_token_hash(&self.storage, &token_hash)
            .await?
            .ok_or(AuthError::InvalidToken)?;

        if invite.accepted_at.is_some() {
            return Err(AuthError::InvalidToken);
        }
        if invite.expires_at < Utc::now() {
            return Err(AuthError::InvalidToken);
        }

        InviteRepository::accept(&self.storage, invite.id).await?;
        let membership =
            OrgRepository::add_member(&self.storage, invite.org_id, user_id, invite.role_id)
                .await?;

        self.events.emit(AuthEvent::InviteAccepted {
            membership: membership.clone(),
        });
        tracing::info!(org_id = %invite.org_id, user_id = %user_id, "invite accepted");
        Ok(membership)
    }

    /// Switch the active org on a session.
    #[instrument(skip(self), fields(session_id = %session_id, org_id = ?org_id))]
    pub async fn switch_org(
        &self,
        session_id: Uuid,
        org_id: Option<Uuid>,
    ) -> Result<authx_core::models::Session> {
        let session = SessionRepository::set_org(&self.storage, session_id, org_id).await?;
        tracing::info!(session_id = %session_id, org_id = ?org_id, "org switched");
        Ok(session)
    }
}
