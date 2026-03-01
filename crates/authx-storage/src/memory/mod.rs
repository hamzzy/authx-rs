use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use authx_core::{
    error::{AuthError, Result, StorageError},
    models::{
        CreateOrg, CreateSession, CreateUser, Membership, Organization, Role, Session, UpdateUser,
        User,
    },
};

use crate::ports::{OrgRepository, SessionRepository, UserRepository};

#[derive(Clone, Default)]
pub struct MemoryStore {
    users:    Arc<RwLock<HashMap<Uuid, User>>>,
    sessions: Arc<RwLock<HashMap<Uuid, Session>>>,
    orgs:     Arc<RwLock<HashMap<Uuid, Organization>>>,
    roles:    Arc<RwLock<HashMap<Uuid, Role>>>,
    memberships: Arc<RwLock<Vec<Membership>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl UserRepository for MemoryStore {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>> {
        Ok(self.users.read().unwrap().get(&id).cloned())
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        Ok(self
            .users
            .read()
            .unwrap()
            .values()
            .find(|u| u.email == email)
            .cloned())
    }

    async fn create(&self, data: CreateUser) -> Result<User> {
        let mut users = self.users.write().unwrap();

        if users.values().any(|u| u.email == data.email) {
            return Err(AuthError::EmailTaken);
        }

        let user = User {
            id:             Uuid::new_v4(),
            email:          data.email,
            email_verified: false,
            created_at:     Utc::now(),
            updated_at:     Utc::now(),
            metadata:       data.metadata.unwrap_or(serde_json::Value::Null),
        };
        users.insert(user.id, user.clone());
        Ok(user)
    }

    async fn update(&self, id: Uuid, data: UpdateUser) -> Result<User> {
        let mut users = self.users.write().unwrap();
        let user = users.get_mut(&id).ok_or(AuthError::UserNotFound)?;

        if let Some(email)          = data.email          { user.email = email; }
        if let Some(verified)       = data.email_verified { user.email_verified = verified; }
        if let Some(meta)           = data.metadata       { user.metadata = meta; }
        user.updated_at = Utc::now();

        Ok(user.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.users
            .write()
            .unwrap()
            .remove(&id)
            .ok_or(AuthError::UserNotFound)?;
        Ok(())
    }
}

#[async_trait]
impl SessionRepository for MemoryStore {
    async fn create(&self, data: CreateSession) -> Result<Session> {
        let session = Session {
            id:          Uuid::new_v4(),
            user_id:     data.user_id,
            token_hash:  data.token_hash,
            device_info: data.device_info,
            ip_address:  data.ip_address,
            org_id:      data.org_id,
            expires_at:  data.expires_at,
            created_at:  Utc::now(),
        };
        self.sessions.write().unwrap().insert(session.id, session.clone());
        Ok(session)
    }

    async fn find_by_token_hash(&self, hash: &str) -> Result<Option<Session>> {
        let session = self
            .sessions
            .read()
            .unwrap()
            .values()
            .find(|s| s.token_hash == hash && s.expires_at > Utc::now())
            .cloned();
        Ok(session)
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<Session>> {
        let sessions = self
            .sessions
            .read()
            .unwrap()
            .values()
            .filter(|s| s.user_id == user_id)
            .cloned()
            .collect();
        Ok(sessions)
    }

    async fn invalidate(&self, session_id: Uuid) -> Result<()> {
        self.sessions
            .write()
            .unwrap()
            .remove(&session_id)
            .ok_or(AuthError::Storage(StorageError::NotFound))?;
        Ok(())
    }

    async fn invalidate_all_for_user(&self, user_id: Uuid) -> Result<()> {
        self.sessions
            .write()
            .unwrap()
            .retain(|_, s| s.user_id != user_id);
        Ok(())
    }
}

#[async_trait]
impl OrgRepository for MemoryStore {
    async fn create(&self, data: CreateOrg) -> Result<Organization> {
        let mut orgs = self.orgs.write().unwrap();
        if orgs.values().any(|o| o.slug == data.slug) {
            return Err(AuthError::Storage(StorageError::Conflict(
                format!("slug '{}' already taken", data.slug),
            )));
        }
        let org = Organization {
            id:         Uuid::new_v4(),
            name:       data.name,
            slug:       data.slug,
            metadata:   data.metadata.unwrap_or(serde_json::Value::Null),
            created_at: Utc::now(),
        };
        orgs.insert(org.id, org.clone());
        Ok(org)
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Organization>> {
        Ok(self.orgs.read().unwrap().get(&id).cloned())
    }

    async fn find_by_slug(&self, slug: &str) -> Result<Option<Organization>> {
        Ok(self
            .orgs
            .read()
            .unwrap()
            .values()
            .find(|o| o.slug == slug)
            .cloned())
    }

    async fn add_member(&self, org_id: Uuid, user_id: Uuid, role_id: Uuid) -> Result<Membership> {
        let role = self
            .roles
            .read()
            .unwrap()
            .get(&role_id)
            .cloned()
            .ok_or(AuthError::Storage(StorageError::NotFound))?;

        let membership = Membership {
            id:         Uuid::new_v4(),
            user_id,
            org_id,
            role,
            created_at: Utc::now(),
        };
        self.memberships.write().unwrap().push(membership.clone());
        Ok(membership)
    }

    async fn remove_member(&self, org_id: Uuid, user_id: Uuid) -> Result<()> {
        let mut memberships = self.memberships.write().unwrap();
        let before = memberships.len();
        memberships.retain(|m| !(m.org_id == org_id && m.user_id == user_id));
        if memberships.len() == before {
            return Err(AuthError::Storage(StorageError::NotFound));
        }
        Ok(())
    }

    async fn get_members(&self, org_id: Uuid) -> Result<Vec<Membership>> {
        Ok(self
            .memberships
            .read()
            .unwrap()
            .iter()
            .filter(|m| m.org_id == org_id)
            .cloned()
            .collect())
    }
}
