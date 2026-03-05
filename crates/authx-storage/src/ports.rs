use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use authx_core::{
    error::Result,
    models::{
        ApiKey, AuditLog, AuthorizationCode, CreateApiKey, CreateAuditLog, CreateAuthorizationCode,
        CreateCredential, CreateDeviceCode, CreateInvite, CreateOidcClient,
        CreateOidcFederationProvider, CreateOidcToken, CreateOrg, CreateSession, CreateUser,
        Credential, CredentialKind, DeviceCode, Invite, Membership, OAuthAccount, OidcClient,
        OidcFederationProvider, OidcToken, Organization, Role, Session, UpdateUser,
        UpsertOAuthAccount, User,
    },
};

#[async_trait]
pub trait UserRepository: Send + Sync + 'static {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>>;
    async fn find_by_email(&self, email: &str) -> Result<Option<User>>;
    async fn find_by_username(&self, username: &str) -> Result<Option<User>>;
    async fn list(&self, offset: u32, limit: u32) -> Result<Vec<User>>;
    async fn create(&self, data: CreateUser) -> Result<User>;
    async fn update(&self, id: Uuid, data: UpdateUser) -> Result<User>;
    async fn delete(&self, id: Uuid) -> Result<()>;
}

#[async_trait]
pub trait SessionRepository: Send + Sync + 'static {
    async fn create(&self, data: CreateSession) -> Result<Session>;
    async fn find_by_token_hash(&self, hash: &str) -> Result<Option<Session>>;
    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<Session>>;
    async fn invalidate(&self, session_id: Uuid) -> Result<()>;
    async fn invalidate_all_for_user(&self, user_id: Uuid) -> Result<()>;
    async fn set_org(&self, session_id: Uuid, org_id: Option<Uuid>) -> Result<Session>;
}

#[async_trait]
pub trait CredentialRepository: Send + Sync + 'static {
    async fn create(&self, data: CreateCredential) -> Result<Credential>;
    async fn find_password_hash(&self, user_id: Uuid) -> Result<Option<String>>;
    async fn find_by_user_and_kind(
        &self,
        user_id: Uuid,
        kind: CredentialKind,
    ) -> Result<Option<Credential>>;
    async fn delete_by_user_and_kind(&self, user_id: Uuid, kind: CredentialKind) -> Result<()>;
}

#[async_trait]
pub trait OrgRepository: Send + Sync + 'static {
    async fn create(&self, data: CreateOrg) -> Result<Organization>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Organization>>;
    async fn find_by_slug(&self, slug: &str) -> Result<Option<Organization>>;
    async fn add_member(&self, org_id: Uuid, user_id: Uuid, role_id: Uuid) -> Result<Membership>;
    async fn remove_member(&self, org_id: Uuid, user_id: Uuid) -> Result<()>;
    async fn get_members(&self, org_id: Uuid) -> Result<Vec<Membership>>;
    async fn find_roles(&self, org_id: Uuid) -> Result<Vec<Role>>;
    async fn create_role(
        &self,
        org_id: Uuid,
        name: String,
        permissions: Vec<String>,
    ) -> Result<Role>;
    async fn update_member_role(
        &self,
        org_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
    ) -> Result<Membership>;
}

#[async_trait]
pub trait AuditLogRepository: Send + Sync + 'static {
    async fn append(&self, entry: CreateAuditLog) -> Result<AuditLog>;
    async fn find_by_user(&self, user_id: Uuid, limit: u32) -> Result<Vec<AuditLog>>;
    async fn find_by_org(&self, org_id: Uuid, limit: u32) -> Result<Vec<AuditLog>>;
}

#[async_trait]
pub trait ApiKeyRepository: Send + Sync + 'static {
    async fn create(&self, data: CreateApiKey) -> Result<ApiKey>;
    async fn find_by_hash(&self, key_hash: &str) -> Result<Option<ApiKey>>;
    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<ApiKey>>;
    async fn revoke(&self, key_id: Uuid, user_id: Uuid) -> Result<()>;
    async fn touch_last_used(&self, key_id: Uuid, at: DateTime<Utc>) -> Result<()>;
}

#[async_trait]
pub trait OAuthAccountRepository: Send + Sync + 'static {
    async fn upsert(&self, data: UpsertOAuthAccount) -> Result<OAuthAccount>;
    async fn find_by_provider(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> Result<Option<OAuthAccount>>;
    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<OAuthAccount>>;
    async fn delete(&self, id: Uuid) -> Result<()>;
}

#[async_trait]
pub trait InviteRepository: Send + Sync + 'static {
    async fn create(&self, data: CreateInvite) -> Result<Invite>;
    async fn find_by_token_hash(&self, hash: &str) -> Result<Option<Invite>>;
    async fn accept(&self, invite_id: Uuid) -> Result<Invite>;
    async fn delete_expired(&self) -> Result<u64>;
}

// ── OIDC Provider (authx as IdP) ───────────────────────────────────────────────

#[async_trait]
pub trait OidcClientRepository: Send + Sync + 'static {
    async fn create(&self, data: CreateOidcClient) -> Result<OidcClient>;
    async fn find_by_client_id(&self, client_id: &str) -> Result<Option<OidcClient>>;
    async fn list(&self, offset: u32, limit: u32) -> Result<Vec<OidcClient>>;
}

#[async_trait]
pub trait AuthorizationCodeRepository: Send + Sync + 'static {
    async fn create(&self, data: CreateAuthorizationCode) -> Result<AuthorizationCode>;
    async fn find_by_code_hash(&self, hash: &str) -> Result<Option<AuthorizationCode>>;
    async fn mark_used(&self, id: Uuid) -> Result<()>;
    async fn delete_expired(&self) -> Result<u64>;
}

#[async_trait]
pub trait OidcTokenRepository: Send + Sync + 'static {
    async fn create(&self, data: CreateOidcToken) -> Result<OidcToken>;
    async fn find_by_token_hash(&self, hash: &str) -> Result<Option<OidcToken>>;
    async fn revoke(&self, id: Uuid) -> Result<()>;
    async fn revoke_all_for_user_client(&self, user_id: Uuid, client_id: &str) -> Result<()>;
}

#[async_trait]
pub trait OidcFederationProviderRepository: Send + Sync + 'static {
    async fn create(&self, data: CreateOidcFederationProvider) -> Result<OidcFederationProvider>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<OidcFederationProvider>>;
    async fn find_by_name(&self, name: &str) -> Result<Option<OidcFederationProvider>>;
    async fn list_enabled(&self) -> Result<Vec<OidcFederationProvider>>;
}

// ── Device Authorization Grant (RFC 8628) ────────────────────────────────────

#[async_trait]
pub trait DeviceCodeRepository: Send + Sync + 'static {
    async fn create(&self, data: CreateDeviceCode) -> Result<DeviceCode>;
    async fn find_by_device_code_hash(&self, hash: &str) -> Result<Option<DeviceCode>>;
    async fn find_by_user_code_hash(&self, hash: &str) -> Result<Option<DeviceCode>>;
    async fn authorize(&self, id: Uuid, user_id: Uuid) -> Result<()>;
    async fn deny(&self, id: Uuid) -> Result<()>;
    async fn update_last_polled(&self, id: Uuid, interval_secs: u32) -> Result<()>;
    async fn delete(&self, id: Uuid) -> Result<()>;
    async fn delete_expired(&self) -> Result<u64>;
    async fn list_by_client(
        &self,
        client_id: &str,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<DeviceCode>>;
}

/// Composite adapter trait — storage backends implement this.
pub trait StorageAdapter:
    UserRepository
    + SessionRepository
    + CredentialRepository
    + OrgRepository
    + AuditLogRepository
    + ApiKeyRepository
    + OAuthAccountRepository
    + InviteRepository
    + OidcClientRepository
    + AuthorizationCodeRepository
    + OidcTokenRepository
    + OidcFederationProviderRepository
    + DeviceCodeRepository
    + Clone
    + Send
    + Sync
    + 'static
{
}

impl<T> StorageAdapter for T where
    T: UserRepository
        + SessionRepository
        + CredentialRepository
        + OrgRepository
        + AuditLogRepository
        + ApiKeyRepository
        + OAuthAccountRepository
        + InviteRepository
        + OidcClientRepository
        + AuthorizationCodeRepository
        + OidcTokenRepository
        + OidcFederationProviderRepository
        + DeviceCodeRepository
        + Clone
        + Send
        + Sync
        + 'static
{
}
