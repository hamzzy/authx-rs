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
        ApiKey, AuditLog, CreateApiKey, CreateAuditLog, CreateCredential, CreateInvite, CreateOrg,
        CreateSession, CreateUser, Credential, CredentialKind, Invite, Membership, OAuthAccount,
        Organization, Role, Session, UpdateUser, UpsertOAuthAccount, User,
    },
};

use crate::ports::{
    ApiKeyRepository, AuditLogRepository, CredentialRepository, InviteRepository,
    OAuthAccountRepository, OrgRepository, SessionRepository, UserRepository,
};

#[derive(Clone, Default)]
pub struct MemoryStore {
    users:          Arc<RwLock<HashMap<Uuid, User>>>,
    sessions:       Arc<RwLock<HashMap<Uuid, Session>>>,
    credentials:    Arc<RwLock<Vec<Credential>>>,
    audit_logs:     Arc<RwLock<Vec<AuditLog>>>,
    orgs:           Arc<RwLock<HashMap<Uuid, Organization>>>,
    roles:          Arc<RwLock<HashMap<Uuid, Role>>>,
    memberships:    Arc<RwLock<Vec<Membership>>>,
    api_keys:       Arc<RwLock<Vec<ApiKey>>>,
    oauth_accounts: Arc<RwLock<Vec<OAuthAccount>>>,
    invites:        Arc<RwLock<Vec<Invite>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

// ── UserRepository ────────────────────────────────────────────────────────────

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

    async fn find_by_username(&self, username: &str) -> Result<Option<User>> {
        Ok(self
            .users
            .read()
            .unwrap()
            .values()
            .find(|u| u.username.as_deref() == Some(username))
            .cloned())
    }

    async fn list(&self, offset: u32, limit: u32) -> Result<Vec<User>> {
        let users = self.users.read().unwrap();
        let mut sorted: Vec<User> = users.values().cloned().collect();
        sorted.sort_by_key(|u| u.created_at);
        Ok(sorted
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn create(&self, data: CreateUser) -> Result<User> {
        let mut users = self.users.write().unwrap();
        if users.values().any(|u| u.email == data.email) {
            return Err(AuthError::EmailTaken);
        }
        if let Some(ref uname) = data.username {
            if users.values().any(|u| u.username.as_deref() == Some(uname.as_str())) {
                return Err(AuthError::Storage(StorageError::Conflict(
                    format!("username '{}' already taken", uname),
                )));
            }
        }
        let user = User {
            id:             Uuid::new_v4(),
            email:          data.email,
            email_verified: false,
            username:       data.username,
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
        if let Some(email)    = data.email          { user.email = email; }
        if let Some(verified) = data.email_verified { user.email_verified = verified; }
        if let Some(uname)    = data.username       { user.username = Some(uname); }
        if let Some(meta)     = data.metadata       { user.metadata = meta; }
        user.updated_at = Utc::now();
        Ok(user.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.users.write().unwrap().remove(&id).ok_or(AuthError::UserNotFound)?;
        Ok(())
    }
}

// ── SessionRepository ─────────────────────────────────────────────────────────

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
        Ok(self
            .sessions
            .read()
            .unwrap()
            .values()
            .find(|s| s.token_hash == hash && s.expires_at > Utc::now())
            .cloned())
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<Session>> {
        Ok(self
            .sessions
            .read()
            .unwrap()
            .values()
            .filter(|s| s.user_id == user_id)
            .cloned()
            .collect())
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
        self.sessions.write().unwrap().retain(|_, s| s.user_id != user_id);
        Ok(())
    }

    async fn set_org(&self, session_id: Uuid, org_id: Option<Uuid>) -> Result<Session> {
        let mut sessions = self.sessions.write().unwrap();
        let session = sessions
            .get_mut(&session_id)
            .ok_or(AuthError::Storage(StorageError::NotFound))?;
        session.org_id = org_id;
        Ok(session.clone())
    }
}

// ── CredentialRepository ──────────────────────────────────────────────────────

#[async_trait]
impl CredentialRepository for MemoryStore {
    async fn create(&self, data: CreateCredential) -> Result<Credential> {
        let cred = Credential {
            id:              Uuid::new_v4(),
            user_id:         data.user_id,
            kind:            data.kind,
            credential_hash: data.credential_hash,
            metadata:        data.metadata.unwrap_or(serde_json::Value::Null),
        };
        self.credentials.write().unwrap().push(cred.clone());
        Ok(cred)
    }

    async fn find_password_hash(&self, user_id: Uuid) -> Result<Option<String>> {
        Ok(self
            .credentials
            .read()
            .unwrap()
            .iter()
            .find(|c| c.user_id == user_id && c.kind == CredentialKind::Password)
            .map(|c| c.credential_hash.clone()))
    }

    async fn find_by_user_and_kind(
        &self,
        user_id: Uuid,
        kind: CredentialKind,
    ) -> Result<Option<Credential>> {
        Ok(self
            .credentials
            .read()
            .unwrap()
            .iter()
            .find(|c| c.user_id == user_id && c.kind == kind)
            .cloned())
    }

    async fn delete_by_user_and_kind(&self, user_id: Uuid, kind: CredentialKind) -> Result<()> {
        let mut creds = self.credentials.write().unwrap();
        let before = creds.len();
        creds.retain(|c| !(c.user_id == user_id && c.kind == kind));
        if creds.len() == before {
            return Err(AuthError::Storage(StorageError::NotFound));
        }
        Ok(())
    }
}

// ── OrgRepository ─────────────────────────────────────────────────────────────

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
            id: Uuid::new_v4(),
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

    async fn find_roles(&self, org_id: Uuid) -> Result<Vec<Role>> {
        Ok(self
            .roles
            .read()
            .unwrap()
            .values()
            .filter(|r| r.org_id == org_id)
            .cloned()
            .collect())
    }

    async fn create_role(&self, org_id: Uuid, name: String, permissions: Vec<String>) -> Result<Role> {
        let role = Role {
            id:          Uuid::new_v4(),
            org_id,
            name,
            permissions,
        };
        self.roles.write().unwrap().insert(role.id, role.clone());
        Ok(role)
    }

    async fn update_member_role(&self, org_id: Uuid, user_id: Uuid, role_id: Uuid) -> Result<Membership> {
        let role = self
            .roles
            .read()
            .unwrap()
            .get(&role_id)
            .cloned()
            .ok_or(AuthError::Storage(StorageError::NotFound))?;

        let mut memberships = self.memberships.write().unwrap();
        let m = memberships
            .iter_mut()
            .find(|m| m.org_id == org_id && m.user_id == user_id)
            .ok_or(AuthError::Storage(StorageError::NotFound))?;
        m.role = role;
        Ok(m.clone())
    }
}

// ── AuditLogRepository ────────────────────────────────────────────────────────

#[async_trait]
impl AuditLogRepository for MemoryStore {
    async fn append(&self, entry: CreateAuditLog) -> Result<AuditLog> {
        let log = AuditLog {
            id:            Uuid::new_v4(),
            user_id:       entry.user_id,
            org_id:        entry.org_id,
            action:        entry.action,
            resource_type: entry.resource_type,
            resource_id:   entry.resource_id,
            ip_address:    entry.ip_address,
            metadata:      entry.metadata.unwrap_or(serde_json::Value::Null),
            created_at:    Utc::now(),
        };
        self.audit_logs.write().unwrap().push(log.clone());
        Ok(log)
    }

    async fn find_by_user(&self, user_id: Uuid, limit: u32) -> Result<Vec<AuditLog>> {
        Ok(self
            .audit_logs
            .read()
            .unwrap()
            .iter()
            .filter(|l| l.user_id == Some(user_id))
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn find_by_org(&self, org_id: Uuid, limit: u32) -> Result<Vec<AuditLog>> {
        Ok(self
            .audit_logs
            .read()
            .unwrap()
            .iter()
            .filter(|l| l.org_id == Some(org_id))
            .take(limit as usize)
            .cloned()
            .collect())
    }
}

// ── ApiKeyRepository ──────────────────────────────────────────────────────────

#[async_trait]
impl ApiKeyRepository for MemoryStore {
    async fn create(&self, data: CreateApiKey) -> Result<ApiKey> {
        let key = ApiKey {
            id:           Uuid::new_v4(),
            user_id:      data.user_id,
            org_id:       data.org_id,
            key_hash:     data.key_hash,
            prefix:       data.prefix,
            name:         data.name,
            scopes:       data.scopes,
            expires_at:   data.expires_at,
            last_used_at: None,
        };
        self.api_keys.write().unwrap().push(key.clone());
        Ok(key)
    }

    async fn find_by_hash(&self, key_hash: &str) -> Result<Option<ApiKey>> {
        Ok(self
            .api_keys
            .read()
            .unwrap()
            .iter()
            .find(|k| k.key_hash == key_hash)
            .cloned())
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<ApiKey>> {
        Ok(self
            .api_keys
            .read()
            .unwrap()
            .iter()
            .filter(|k| k.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn revoke(&self, key_id: Uuid, user_id: Uuid) -> Result<()> {
        let mut keys = self.api_keys.write().unwrap();
        let before = keys.len();
        keys.retain(|k| !(k.id == key_id && k.user_id == user_id));
        if keys.len() == before {
            return Err(AuthError::Storage(StorageError::NotFound));
        }
        Ok(())
    }

    async fn touch_last_used(&self, key_id: Uuid, at: chrono::DateTime<Utc>) -> Result<()> {
        let mut keys = self.api_keys.write().unwrap();
        if let Some(k) = keys.iter_mut().find(|k| k.id == key_id) {
            k.last_used_at = Some(at);
        }
        Ok(())
    }
}

// ── OAuthAccountRepository ────────────────────────────────────────────────────

#[async_trait]
impl OAuthAccountRepository for MemoryStore {
    async fn upsert(&self, data: UpsertOAuthAccount) -> Result<OAuthAccount> {
        let mut accounts = self.oauth_accounts.write().unwrap();
        if let Some(existing) = accounts
            .iter_mut()
            .find(|a| a.provider == data.provider && a.provider_user_id == data.provider_user_id)
        {
            existing.access_token_enc  = data.access_token_enc;
            existing.refresh_token_enc = data.refresh_token_enc;
            existing.expires_at        = data.expires_at;
            return Ok(existing.clone());
        }
        let account = OAuthAccount {
            id:                Uuid::new_v4(),
            user_id:           data.user_id,
            provider:          data.provider,
            provider_user_id:  data.provider_user_id,
            access_token_enc:  data.access_token_enc,
            refresh_token_enc: data.refresh_token_enc,
            expires_at:        data.expires_at,
        };
        accounts.push(account.clone());
        Ok(account)
    }

    async fn find_by_provider(&self, provider: &str, provider_user_id: &str) -> Result<Option<OAuthAccount>> {
        Ok(self
            .oauth_accounts
            .read()
            .unwrap()
            .iter()
            .find(|a| a.provider == provider && a.provider_user_id == provider_user_id)
            .cloned())
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<OAuthAccount>> {
        Ok(self
            .oauth_accounts
            .read()
            .unwrap()
            .iter()
            .filter(|a| a.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        let mut accounts = self.oauth_accounts.write().unwrap();
        let before = accounts.len();
        accounts.retain(|a| a.id != id);
        if accounts.len() == before {
            return Err(AuthError::Storage(StorageError::NotFound));
        }
        Ok(())
    }
}

// ── InviteRepository ──────────────────────────────────────────────────────────

#[async_trait]
impl InviteRepository for MemoryStore {
    async fn create(&self, data: CreateInvite) -> Result<Invite> {
        let invite = Invite {
            id:          Uuid::new_v4(),
            org_id:      data.org_id,
            email:       data.email,
            role_id:     data.role_id,
            token_hash:  data.token_hash,
            expires_at:  data.expires_at,
            accepted_at: None,
        };
        self.invites.write().unwrap().push(invite.clone());
        Ok(invite)
    }

    async fn find_by_token_hash(&self, hash: &str) -> Result<Option<Invite>> {
        Ok(self
            .invites
            .read()
            .unwrap()
            .iter()
            .find(|i| i.token_hash == hash)
            .cloned())
    }

    async fn accept(&self, invite_id: Uuid) -> Result<Invite> {
        let mut invites = self.invites.write().unwrap();
        let invite = invites
            .iter_mut()
            .find(|i| i.id == invite_id)
            .ok_or(AuthError::Storage(StorageError::NotFound))?;
        invite.accepted_at = Some(Utc::now());
        Ok(invite.clone())
    }

    async fn delete_expired(&self) -> Result<u64> {
        let mut invites = self.invites.write().unwrap();
        let before = invites.len();
        let now = Utc::now();
        invites.retain(|i| i.accepted_at.is_some() || i.expires_at > now);
        Ok((before - invites.len()) as u64)
    }
}
