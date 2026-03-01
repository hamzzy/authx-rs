use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
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

// ── Store ─────────────────────────────────────────────────────────────────────

/// Postgres-backed storage adapter.
///
/// Wrap a [`PgPool`] and pass this to [`AuthxState::new`].
#[derive(Clone)]
pub struct PostgresStore {
    pub pool: PgPool,
}

impl PostgresStore {
    pub async fn connect(database_url: &str) -> std::result::Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;
        tracing::info!("postgres pool connected");
        Ok(Self { pool })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn migrate(pool: &PgPool) -> std::result::Result<(), sqlx::migrate::MigrateError> {
        sqlx::migrate!("src/sqlx/migrations").run(pool).await?;
        tracing::info!("database migrations applied");
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn db_err(e: sqlx::Error) -> AuthError {
    match e {
        sqlx::Error::RowNotFound => AuthError::Storage(StorageError::NotFound),
        sqlx::Error::Database(ref dbe) if dbe.constraint().is_some() => {
            AuthError::Storage(StorageError::Conflict(dbe.message().to_owned()))
        }
        other => AuthError::Storage(StorageError::Database(other.to_string())),
    }
}

fn credential_kind_str(k: &CredentialKind) -> &'static str {
    match k {
        CredentialKind::Password => "password",
        CredentialKind::Passkey => "passkey",
        CredentialKind::OauthToken => "oauth_token",
    }
}

fn credential_kind_from_str(s: &str) -> CredentialKind {
    match s {
        "passkey" => CredentialKind::Passkey,
        "oauth_token" => CredentialKind::OauthToken,
        _ => CredentialKind::Password,
    }
}

fn map_user(r: &sqlx::postgres::PgRow) -> User {
    User {
        id: r.get("id"),
        email: r.get("email"),
        email_verified: r.get("email_verified"),
        username: r.get("username"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
        metadata: r.get::<serde_json::Value, _>("metadata"),
    }
}

fn map_session(r: &sqlx::postgres::PgRow) -> Session {
    Session {
        id: r.get("id"),
        user_id: r.get("user_id"),
        token_hash: r.get("token_hash"),
        device_info: r.get::<serde_json::Value, _>("device_info"),
        ip_address: r.get("ip_address"),
        org_id: r.get("org_id"),
        expires_at: r.get("expires_at"),
        created_at: r.get("created_at"),
    }
}

fn map_audit_log(r: &sqlx::postgres::PgRow) -> AuditLog {
    AuditLog {
        id: r.get("id"),
        user_id: r.get("user_id"),
        org_id: r.get("org_id"),
        action: r.get("action"),
        resource_type: r.get("resource_type"),
        resource_id: r.get("resource_id"),
        ip_address: r.get("ip_address"),
        metadata: r.get::<serde_json::Value, _>("metadata"),
        created_at: r.get("created_at"),
    }
}

// ── UserRepository ────────────────────────────────────────────────────────────

#[async_trait]
impl UserRepository for PostgresStore {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, email, email_verified, username, created_at, updated_at, metadata \
             FROM authx_users WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.as_ref().map(map_user))
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, email, email_verified, username, created_at, updated_at, metadata \
             FROM authx_users WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.as_ref().map(map_user))
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, email, email_verified, username, created_at, updated_at, metadata \
             FROM authx_users WHERE username = $1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.as_ref().map(map_user))
    }

    async fn list(&self, offset: u32, limit: u32) -> Result<Vec<User>> {
        let rows = sqlx::query(
            "SELECT id, email, email_verified, username, created_at, updated_at, metadata \
             FROM authx_users ORDER BY created_at ASC LIMIT $1 OFFSET $2",
        )
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(rows.iter().map(map_user).collect())
    }

    async fn create(&self, data: CreateUser) -> Result<User> {
        let meta = data.metadata.unwrap_or(serde_json::Value::Null);
        let row = sqlx::query(
            "INSERT INTO authx_users (id, email, email_verified, username, metadata) \
             VALUES ($1, $2, false, $3, $4) \
             RETURNING id, email, email_verified, username, created_at, updated_at, metadata",
        )
        .bind(Uuid::new_v4())
        .bind(&data.email)
        .bind(data.username.as_deref())
        .bind(&meta)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref dbe) = e {
                if dbe.constraint() == Some("authx_users_email_key") {
                    return AuthError::EmailTaken;
                }
                if dbe.constraint() == Some("authx_users_username_key") {
                    return AuthError::Storage(StorageError::Conflict(
                        "username already taken".into(),
                    ));
                }
            }
            db_err(e)
        })?;

        tracing::debug!(email = %data.email, "user row inserted");
        Ok(map_user(&row))
    }

    async fn update(&self, id: Uuid, data: UpdateUser) -> Result<User> {
        let row = sqlx::query(
            "UPDATE authx_users \
             SET \
               email          = COALESCE($2, email), \
               email_verified = COALESCE($3, email_verified), \
               username       = COALESCE($4, username), \
               metadata       = COALESCE($5, metadata), \
               updated_at     = NOW() \
             WHERE id = $1 \
             RETURNING id, email, email_verified, username, created_at, updated_at, metadata",
        )
        .bind(id)
        .bind(data.email.as_deref())
        .bind(data.email_verified)
        .bind(data.username.as_deref())
        .bind(data.metadata.as_ref())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?
        .ok_or(AuthError::UserNotFound)?;

        tracing::debug!(user_id = %id, "user row updated");
        Ok(map_user(&row))
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM authx_users WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;

        if result.rows_affected() == 0 {
            return Err(AuthError::UserNotFound);
        }
        tracing::debug!(user_id = %id, "user row deleted");
        Ok(())
    }
}

// ── SessionRepository ─────────────────────────────────────────────────────────

#[async_trait]
impl SessionRepository for PostgresStore {
    async fn create(&self, data: CreateSession) -> Result<Session> {
        let row = sqlx::query(
            "INSERT INTO authx_sessions \
               (id, user_id, token_hash, device_info, ip_address, org_id, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             RETURNING id, user_id, token_hash, device_info, ip_address, org_id, expires_at, created_at",
        )
        .bind(Uuid::new_v4())
        .bind(data.user_id)
        .bind(&data.token_hash)
        .bind(&data.device_info)
        .bind(&data.ip_address)
        .bind(data.org_id)
        .bind(data.expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;

        tracing::debug!(user_id = %data.user_id, "session row inserted");
        Ok(map_session(&row))
    }

    async fn find_by_token_hash(&self, hash: &str) -> Result<Option<Session>> {
        let row = sqlx::query(
            "SELECT id, user_id, token_hash, device_info, ip_address, org_id, expires_at, created_at \
             FROM authx_sessions WHERE token_hash = $1 AND expires_at > NOW()",
        )
        .bind(hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.as_ref().map(map_session))
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<Session>> {
        let rows = sqlx::query(
            "SELECT id, user_id, token_hash, device_info, ip_address, org_id, expires_at, created_at \
             FROM authx_sessions WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(rows.iter().map(map_session).collect())
    }

    async fn invalidate(&self, session_id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM authx_sessions WHERE id = $1")
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;

        if result.rows_affected() == 0 {
            return Err(AuthError::SessionNotFound);
        }
        tracing::debug!(session_id = %session_id, "session invalidated");
        Ok(())
    }

    async fn invalidate_all_for_user(&self, user_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM authx_sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        tracing::debug!(user_id = %user_id, "all user sessions invalidated");
        Ok(())
    }

    async fn set_org(&self, session_id: Uuid, org_id: Option<Uuid>) -> Result<Session> {
        let row = sqlx::query(
            "UPDATE authx_sessions SET org_id = $2 WHERE id = $1 \
             RETURNING id, user_id, token_hash, device_info, ip_address, org_id, expires_at, created_at",
        )
        .bind(session_id)
        .bind(org_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?
        .ok_or(AuthError::SessionNotFound)?;

        tracing::debug!(session_id = %session_id, "session org updated");
        Ok(map_session(&row))
    }
}

// ── CredentialRepository ──────────────────────────────────────────────────────

#[async_trait]
impl CredentialRepository for PostgresStore {
    async fn create(&self, data: CreateCredential) -> Result<Credential> {
        let kind_str = credential_kind_str(&data.kind);
        let meta = data.metadata.unwrap_or(serde_json::Value::Null);

        let row = sqlx::query(
            "INSERT INTO authx_credentials (id, user_id, kind, credential_hash, metadata) \
             VALUES ($1, $2, $3, $4, $5) \
             RETURNING id, user_id, kind, credential_hash, metadata",
        )
        .bind(Uuid::new_v4())
        .bind(data.user_id)
        .bind(kind_str)
        .bind(&data.credential_hash)
        .bind(&meta)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;

        tracing::debug!(user_id = %data.user_id, kind = kind_str, "credential inserted");
        Ok(Credential {
            id: row.get("id"),
            user_id: row.get("user_id"),
            kind: credential_kind_from_str(row.get("kind")),
            credential_hash: row.get("credential_hash"),
            metadata: row.get::<serde_json::Value, _>("metadata"),
        })
    }

    async fn find_password_hash(&self, user_id: Uuid) -> Result<Option<String>> {
        let row = sqlx::query(
            "SELECT credential_hash FROM authx_credentials \
             WHERE user_id = $1 AND kind = 'password'",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.map(|r| r.get("credential_hash")))
    }

    async fn find_by_user_and_kind(
        &self,
        user_id: Uuid,
        kind: CredentialKind,
    ) -> Result<Option<Credential>> {
        let row = sqlx::query(
            "SELECT id, user_id, kind, credential_hash, metadata \
             FROM authx_credentials WHERE user_id = $1 AND kind = $2",
        )
        .bind(user_id)
        .bind(credential_kind_str(&kind))
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;

        Ok(row.map(|r| Credential {
            id: r.get("id"),
            user_id: r.get("user_id"),
            kind: credential_kind_from_str(r.get("kind")),
            credential_hash: r.get("credential_hash"),
            metadata: r.get::<serde_json::Value, _>("metadata"),
        }))
    }

    async fn delete_by_user_and_kind(&self, user_id: Uuid, kind: CredentialKind) -> Result<()> {
        let result = sqlx::query("DELETE FROM authx_credentials WHERE user_id = $1 AND kind = $2")
            .bind(user_id)
            .bind(credential_kind_str(&kind))
            .execute(&self.pool)
            .await
            .map_err(db_err)?;

        if result.rows_affected() == 0 {
            return Err(AuthError::Storage(StorageError::NotFound));
        }
        Ok(())
    }
}

// ── OrgRepository ─────────────────────────────────────────────────────────────

fn map_org(r: &sqlx::postgres::PgRow) -> Organization {
    Organization {
        id: r.get("id"),
        name: r.get("name"),
        slug: r.get("slug"),
        metadata: r.get::<serde_json::Value, _>("metadata"),
        created_at: r.get("created_at"),
    }
}

fn map_membership(r: &sqlx::postgres::PgRow) -> Membership {
    Membership {
        id: r.get("id"),
        user_id: r.get("user_id"),
        org_id: r.get("org_id"),
        role: Role {
            id: r.get("role_id"),
            org_id: r.get("role_org_id"),
            name: r.get("role_name"),
            permissions: r.get::<Vec<String>, _>("permissions"),
        },
        created_at: r.get("created_at"),
    }
}

#[async_trait]
impl OrgRepository for PostgresStore {
    async fn create(&self, data: CreateOrg) -> Result<Organization> {
        let meta = data.metadata.unwrap_or(serde_json::Value::Null);
        let row = sqlx::query(
            "INSERT INTO authx_orgs (id, name, slug, metadata) \
             VALUES ($1, $2, $3, $4) \
             RETURNING id, name, slug, metadata, created_at",
        )
        .bind(Uuid::new_v4())
        .bind(&data.name)
        .bind(&data.slug)
        .bind(&meta)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref dbe) = e {
                if dbe.constraint() == Some("authx_orgs_slug_key") {
                    return AuthError::Storage(StorageError::Conflict(format!(
                        "slug '{}' already taken",
                        data.slug
                    )));
                }
            }
            db_err(e)
        })?;

        tracing::debug!(slug = %data.slug, "org row inserted");
        Ok(map_org(&row))
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Organization>> {
        let row = sqlx::query(
            "SELECT id, name, slug, metadata, created_at FROM authx_orgs WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.as_ref().map(map_org))
    }

    async fn find_by_slug(&self, slug: &str) -> Result<Option<Organization>> {
        let row = sqlx::query(
            "SELECT id, name, slug, metadata, created_at FROM authx_orgs WHERE slug = $1",
        )
        .bind(slug)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.as_ref().map(map_org))
    }

    async fn add_member(&self, org_id: Uuid, user_id: Uuid, role_id: Uuid) -> Result<Membership> {
        let role_row =
            sqlx::query("SELECT id, org_id, name, permissions FROM authx_roles WHERE id = $1")
                .bind(role_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?
                .ok_or(AuthError::Storage(StorageError::NotFound))?;

        let role = Role {
            id: role_row.get("id"),
            org_id: role_row.get("org_id"),
            name: role_row.get("name"),
            permissions: role_row.get::<Vec<String>, _>("permissions"),
        };

        let row = sqlx::query(
            "INSERT INTO authx_memberships (id, user_id, org_id, role_id) \
             VALUES ($1, $2, $3, $4) \
             RETURNING id, user_id, org_id, created_at",
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(org_id)
        .bind(role_id)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;

        tracing::debug!(org_id = %org_id, user_id = %user_id, "member added");
        Ok(Membership {
            id: row.get("id"),
            user_id: row.get("user_id"),
            org_id: row.get("org_id"),
            role,
            created_at: row.get("created_at"),
        })
    }

    async fn remove_member(&self, org_id: Uuid, user_id: Uuid) -> Result<()> {
        let result =
            sqlx::query("DELETE FROM authx_memberships WHERE org_id = $1 AND user_id = $2")
                .bind(org_id)
                .bind(user_id)
                .execute(&self.pool)
                .await
                .map_err(db_err)?;

        if result.rows_affected() == 0 {
            return Err(AuthError::Storage(StorageError::NotFound));
        }
        Ok(())
    }

    async fn get_members(&self, org_id: Uuid) -> Result<Vec<Membership>> {
        let rows = sqlx::query(
            "SELECT m.id, m.user_id, m.org_id, m.created_at, \
                    r.id AS role_id, r.org_id AS role_org_id, r.name AS role_name, r.permissions \
             FROM authx_memberships m \
             JOIN authx_roles r ON r.id = m.role_id \
             WHERE m.org_id = $1",
        )
        .bind(org_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(rows.iter().map(map_membership).collect())
    }

    async fn find_roles(&self, org_id: Uuid) -> Result<Vec<Role>> {
        let rows =
            sqlx::query("SELECT id, org_id, name, permissions FROM authx_roles WHERE org_id = $1")
                .bind(org_id)
                .fetch_all(&self.pool)
                .await
                .map_err(db_err)?;
        Ok(rows
            .iter()
            .map(|r| Role {
                id: r.get("id"),
                org_id: r.get("org_id"),
                name: r.get("name"),
                permissions: r.get::<Vec<String>, _>("permissions"),
            })
            .collect())
    }

    async fn create_role(
        &self,
        org_id: Uuid,
        name: String,
        permissions: Vec<String>,
    ) -> Result<Role> {
        let row = sqlx::query(
            "INSERT INTO authx_roles (id, org_id, name, permissions) \
             VALUES ($1, $2, $3, $4) \
             RETURNING id, org_id, name, permissions",
        )
        .bind(Uuid::new_v4())
        .bind(org_id)
        .bind(&name)
        .bind(&permissions)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;

        tracing::debug!(org_id = %org_id, name = %name, "role created");
        Ok(Role {
            id: row.get("id"),
            org_id: row.get("org_id"),
            name: row.get("name"),
            permissions: row.get::<Vec<String>, _>("permissions"),
        })
    }

    async fn update_member_role(
        &self,
        org_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
    ) -> Result<Membership> {
        sqlx::query("UPDATE authx_memberships SET role_id = $3 WHERE org_id = $1 AND user_id = $2")
            .bind(org_id)
            .bind(user_id)
            .bind(role_id)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;

        let rows = sqlx::query(
            "SELECT m.id, m.user_id, m.org_id, m.created_at, \
                    r.id AS role_id, r.org_id AS role_org_id, r.name AS role_name, r.permissions \
             FROM authx_memberships m \
             JOIN authx_roles r ON r.id = m.role_id \
             WHERE m.org_id = $1 AND m.user_id = $2",
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?
        .ok_or(AuthError::Storage(StorageError::NotFound))?;

        Ok(map_membership(&rows))
    }
}

// ── AuditLogRepository ────────────────────────────────────────────────────────

#[async_trait]
impl AuditLogRepository for PostgresStore {
    async fn append(&self, entry: CreateAuditLog) -> Result<AuditLog> {
        let meta = entry.metadata.unwrap_or(serde_json::Value::Null);
        let row = sqlx::query(
            "INSERT INTO authx_audit_logs \
               (id, user_id, org_id, action, resource_type, resource_id, ip_address, metadata) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             RETURNING id, user_id, org_id, action, resource_type, resource_id, ip_address, metadata, created_at",
        )
        .bind(Uuid::new_v4())
        .bind(entry.user_id)
        .bind(entry.org_id)
        .bind(&entry.action)
        .bind(&entry.resource_type)
        .bind(entry.resource_id.as_deref())
        .bind(&entry.ip_address)
        .bind(&meta)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;

        tracing::debug!(action = %entry.action, "audit log appended");
        Ok(map_audit_log(&row))
    }

    async fn find_by_user(&self, user_id: Uuid, limit: u32) -> Result<Vec<AuditLog>> {
        let rows = sqlx::query(
            "SELECT id, user_id, org_id, action, resource_type, resource_id, ip_address, metadata, created_at \
             FROM authx_audit_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2",
        )
        .bind(user_id)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(rows.iter().map(map_audit_log).collect())
    }

    async fn find_by_org(&self, org_id: Uuid, limit: u32) -> Result<Vec<AuditLog>> {
        let rows = sqlx::query(
            "SELECT id, user_id, org_id, action, resource_type, resource_id, ip_address, metadata, created_at \
             FROM authx_audit_logs WHERE org_id = $1 ORDER BY created_at DESC LIMIT $2",
        )
        .bind(org_id)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(rows.iter().map(map_audit_log).collect())
    }
}

// ── ApiKeyRepository ──────────────────────────────────────────────────────────

fn map_api_key(r: &sqlx::postgres::PgRow) -> ApiKey {
    ApiKey {
        id: r.get("id"),
        user_id: r.get("user_id"),
        org_id: r.get("org_id"),
        key_hash: r.get("key_hash"),
        prefix: r.get("prefix"),
        name: r.get("name"),
        scopes: r.get::<Vec<String>, _>("scopes"),
        expires_at: r.get("expires_at"),
        last_used_at: r.get("last_used_at"),
    }
}

#[async_trait]
impl ApiKeyRepository for PostgresStore {
    async fn create(&self, data: CreateApiKey) -> Result<ApiKey> {
        let row = sqlx::query(
            "INSERT INTO authx_api_keys \
               (id, user_id, org_id, key_hash, prefix, name, scopes, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             RETURNING id, user_id, org_id, key_hash, prefix, name, scopes, expires_at, last_used_at",
        )
        .bind(Uuid::new_v4())
        .bind(data.user_id)
        .bind(data.org_id)
        .bind(&data.key_hash)
        .bind(&data.prefix)
        .bind(&data.name)
        .bind(&data.scopes)
        .bind(data.expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;

        tracing::debug!(user_id = %data.user_id, "api key created");
        Ok(map_api_key(&row))
    }

    async fn find_by_hash(&self, key_hash: &str) -> Result<Option<ApiKey>> {
        let row = sqlx::query(
            "SELECT id, user_id, org_id, key_hash, prefix, name, scopes, expires_at, last_used_at \
             FROM authx_api_keys WHERE key_hash = $1",
        )
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.as_ref().map(map_api_key))
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<ApiKey>> {
        let rows = sqlx::query(
            "SELECT id, user_id, org_id, key_hash, prefix, name, scopes, expires_at, last_used_at \
             FROM authx_api_keys WHERE user_id = $1 ORDER BY id",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(rows.iter().map(map_api_key).collect())
    }

    async fn revoke(&self, key_id: Uuid, user_id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM authx_api_keys WHERE id = $1 AND user_id = $2")
            .bind(key_id)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;

        if result.rows_affected() == 0 {
            return Err(AuthError::Storage(StorageError::NotFound));
        }
        tracing::debug!(key_id = %key_id, "api key revoked");
        Ok(())
    }

    async fn touch_last_used(&self, key_id: Uuid, at: DateTime<Utc>) -> Result<()> {
        sqlx::query("UPDATE authx_api_keys SET last_used_at = $2 WHERE id = $1")
            .bind(key_id)
            .bind(at)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(())
    }
}

// ── OAuthAccountRepository ────────────────────────────────────────────────────

fn map_oauth_account(r: &sqlx::postgres::PgRow) -> OAuthAccount {
    OAuthAccount {
        id: r.get("id"),
        user_id: r.get("user_id"),
        provider: r.get("provider"),
        provider_user_id: r.get("provider_user_id"),
        access_token_enc: r.get("access_token_enc"),
        refresh_token_enc: r.get("refresh_token_enc"),
        expires_at: r.get("expires_at"),
    }
}

#[async_trait]
impl OAuthAccountRepository for PostgresStore {
    async fn upsert(&self, data: UpsertOAuthAccount) -> Result<OAuthAccount> {
        let row = sqlx::query(
            "INSERT INTO authx_oauth_accounts \
               (id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (provider, provider_user_id) DO UPDATE SET \
               access_token_enc  = EXCLUDED.access_token_enc, \
               refresh_token_enc = EXCLUDED.refresh_token_enc, \
               expires_at        = EXCLUDED.expires_at \
             RETURNING id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, expires_at",
        )
        .bind(Uuid::new_v4())
        .bind(data.user_id)
        .bind(&data.provider)
        .bind(&data.provider_user_id)
        .bind(&data.access_token_enc)
        .bind(data.refresh_token_enc.as_deref())
        .bind(data.expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;

        tracing::debug!(provider = %data.provider, user_id = %data.user_id, "oauth account upserted");
        Ok(map_oauth_account(&row))
    }

    async fn find_by_provider(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> Result<Option<OAuthAccount>> {
        let row = sqlx::query(
            "SELECT id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, expires_at \
             FROM authx_oauth_accounts WHERE provider = $1 AND provider_user_id = $2",
        )
        .bind(provider)
        .bind(provider_user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.as_ref().map(map_oauth_account))
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<OAuthAccount>> {
        let rows = sqlx::query(
            "SELECT id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, expires_at \
             FROM authx_oauth_accounts WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(rows.iter().map(map_oauth_account).collect())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM authx_oauth_accounts WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;

        if result.rows_affected() == 0 {
            return Err(AuthError::Storage(StorageError::NotFound));
        }
        Ok(())
    }
}

// ── InviteRepository ──────────────────────────────────────────────────────────

fn map_invite(r: &sqlx::postgres::PgRow) -> Invite {
    Invite {
        id: r.get("id"),
        org_id: r.get("org_id"),
        email: r.get("email"),
        role_id: r.get("role_id"),
        token_hash: r.get("token_hash"),
        expires_at: r.get("expires_at"),
        accepted_at: r.get("accepted_at"),
    }
}

#[async_trait]
impl InviteRepository for PostgresStore {
    async fn create(&self, data: CreateInvite) -> Result<Invite> {
        let row = sqlx::query(
            "INSERT INTO authx_invites (id, org_id, email, role_id, token_hash, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             RETURNING id, org_id, email, role_id, token_hash, expires_at, accepted_at",
        )
        .bind(Uuid::new_v4())
        .bind(data.org_id)
        .bind(&data.email)
        .bind(data.role_id)
        .bind(&data.token_hash)
        .bind(data.expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;

        tracing::debug!(org_id = %data.org_id, email = %data.email, "invite created");
        Ok(map_invite(&row))
    }

    async fn find_by_token_hash(&self, hash: &str) -> Result<Option<Invite>> {
        let row = sqlx::query(
            "SELECT id, org_id, email, role_id, token_hash, expires_at, accepted_at \
             FROM authx_invites WHERE token_hash = $1",
        )
        .bind(hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.as_ref().map(map_invite))
    }

    async fn accept(&self, invite_id: Uuid) -> Result<Invite> {
        let row = sqlx::query(
            "UPDATE authx_invites SET accepted_at = NOW() WHERE id = $1 \
             RETURNING id, org_id, email, role_id, token_hash, expires_at, accepted_at",
        )
        .bind(invite_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?
        .ok_or(AuthError::Storage(StorageError::NotFound))?;

        Ok(map_invite(&row))
    }

    async fn delete_expired(&self) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM authx_invites WHERE accepted_at IS NULL AND expires_at < NOW()",
        )
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected())
    }
}
