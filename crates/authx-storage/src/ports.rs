use async_trait::async_trait;
use uuid::Uuid;

use authx_core::{
    error::Result,
    models::{
        CreateOrg, CreateSession, CreateUser, Membership, Organization, Session, UpdateUser, User,
    },
};

#[async_trait]
pub trait UserRepository: Send + Sync + 'static {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>>;
    async fn find_by_email(&self, email: &str) -> Result<Option<User>>;
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
}

#[async_trait]
pub trait OrgRepository: Send + Sync + 'static {
    async fn create(&self, data: CreateOrg) -> Result<Organization>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Organization>>;
    async fn find_by_slug(&self, slug: &str) -> Result<Option<Organization>>;
    async fn add_member(&self, org_id: Uuid, user_id: Uuid, role_id: Uuid) -> Result<Membership>;
    async fn remove_member(&self, org_id: Uuid, user_id: Uuid) -> Result<()>;
    async fn get_members(&self, org_id: Uuid) -> Result<Vec<Membership>>;
}

/// Composite adapter trait implemented by storage backends.
pub trait StorageAdapter: UserRepository + SessionRepository + OrgRepository + Clone + Send + Sync + 'static {}

impl<T> StorageAdapter for T where
    T: UserRepository + SessionRepository + OrgRepository + Clone + Send + Sync + 'static
{}
