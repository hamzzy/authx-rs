use async_trait::async_trait;
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use uuid::Uuid;

use authx_core::{
    error::{AuthError, Result, StorageError},
    models::{
        AuditLog, CreateAuditLog, CreateCredential, CreateOrg, CreateSession, CreateUser,
        Credential, CredentialKind, Membership, Organization, Role, Session, UpdateUser, User,
    },
};

use crate::ports::{AuditLogRepository, CredentialRepository, OrgRepository, SessionRepository, UserRepository};

// ── Store ─────────────────────────────────────────────────────────────────────

/// Postgres-backed storage adapter.
///
/// Wrap a [`PgPool`] (obtained from [`PostgresStore::connect`] or passed in
/// directly) and pass this to [`AuthxState::new`].
///
/// # Example
/// ```rust,ignore
/// let store = PostgresStore::connect("postgres://user:pass@localhost/authx").await?;
/// PostgresStore::migrate(&store.pool).await?;
/// let state = AuthxState::new(store, 60 * 60 * 24 * 30, true);
/// ```
#[derive(Clone)]
pub struct PostgresStore {
    pub pool: PgPool,
}

impl PostgresStore {
    /// Open a connection pool and return a ready store.
    pub async fn connect(database_url: &str) -> std::result::Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;
        tracing::info!("postgres pool connected");
        Ok(Self { pool })
    }

    /// Wrap an existing pool (useful in tests or when you manage the pool yourself).
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Run embedded migrations — call once at startup before serving requests.
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
        CredentialKind::Password   => "password",
        CredentialKind::Passkey    => "passkey",
        CredentialKind::OauthToken => "oauth_token",
    }
}

fn credential_kind_from_str(s: &str) -> CredentialKind {
    match s {
        "passkey"     => CredentialKind::Passkey,
        "oauth_token" => CredentialKind::OauthToken,
        _             => CredentialKind::Password,
    }
}

// ── UserRepository ────────────────────────────────────────────────────────────

#[async_trait]
impl UserRepository for PostgresStore {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, email, email_verified, created_at, updated_at, metadata \
             FROM authx_users WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;

        Ok(row.map(|r| User {
            id:             r.get("id"),
            email:          r.get("email"),
            email_verified: r.get("email_verified"),
            created_at:     r.get("created_at"),
            updated_at:     r.get("updated_at"),
            metadata:       r.get::<serde_json::Value, _>("metadata"),
        }))
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, email, email_verified, created_at, updated_at, metadata \
             FROM authx_users WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;

        Ok(row.map(|r| User {
            id:             r.get("id"),
            email:          r.get("email"),
            email_verified: r.get("email_verified"),
            created_at:     r.get("created_at"),
            updated_at:     r.get("updated_at"),
            metadata:       r.get::<serde_json::Value, _>("metadata"),
        }))
    }

    async fn create(&self, data: CreateUser) -> Result<User> {
        let meta = data.metadata.unwrap_or(serde_json::Value::Null);
        let row = sqlx::query(
            "INSERT INTO authx_users (id, email, email_verified, metadata) \
             VALUES ($1, $2, false, $3) \
             RETURNING id, email, email_verified, created_at, updated_at, metadata",
        )
        .bind(Uuid::new_v4())
        .bind(&data.email)
        .bind(&meta)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref dbe) = e {
                if dbe.constraint() == Some("authx_users_email_key") {
                    return AuthError::EmailTaken;
                }
            }
            db_err(e)
        })?;

        tracing::debug!(email = %data.email, "user row inserted");
        Ok(User {
            id:             row.get("id"),
            email:          row.get("email"),
            email_verified: row.get("email_verified"),
            created_at:     row.get("created_at"),
            updated_at:     row.get("updated_at"),
            metadata:       row.get::<serde_json::Value, _>("metadata"),
        })
    }

    async fn update(&self, id: Uuid, data: UpdateUser) -> Result<User> {
        // Build a targeted update — only touch provided fields.
        let row = sqlx::query(
            "UPDATE authx_users \
             SET \
               email          = COALESCE($2, email), \
               email_verified = COALESCE($3, email_verified), \
               metadata       = COALESCE($4, metadata), \
               updated_at     = NOW() \
             WHERE id = $1 \
             RETURNING id, email, email_verified, created_at, updated_at, metadata",
        )
        .bind(id)
        .bind(data.email.as_deref())
        .bind(data.email_verified)
        .bind(data.metadata.as_ref())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?
        .ok_or(AuthError::UserNotFound)?;

        tracing::debug!(user_id = %id, "user row updated");
        Ok(User {
            id:             row.get("id"),
            email:          row.get("email"),
            email_verified: row.get("email_verified"),
            created_at:     row.get("created_at"),
            updated_at:     row.get("updated_at"),
            metadata:       row.get::<serde_json::Value, _>("metadata"),
        })
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
        Ok(Session {
            id:          row.get("id"),
            user_id:     row.get("user_id"),
            token_hash:  row.get("token_hash"),
            device_info: row.get::<serde_json::Value, _>("device_info"),
            ip_address:  row.get("ip_address"),
            org_id:      row.get("org_id"),
            expires_at:  row.get("expires_at"),
            created_at:  row.get("created_at"),
        })
    }

    async fn find_by_token_hash(&self, hash: &str) -> Result<Option<Session>> {
        let row = sqlx::query(
            "SELECT id, user_id, token_hash, device_info, ip_address, org_id, expires_at, created_at \
             FROM authx_sessions \
             WHERE token_hash = $1 AND expires_at > NOW()",
        )
        .bind(hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;

        Ok(row.map(|r| Session {
            id:          r.get("id"),
            user_id:     r.get("user_id"),
            token_hash:  r.get("token_hash"),
            device_info: r.get::<serde_json::Value, _>("device_info"),
            ip_address:  r.get("ip_address"),
            org_id:      r.get("org_id"),
            expires_at:  r.get("expires_at"),
            created_at:  r.get("created_at"),
        }))
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

        Ok(rows.into_iter().map(|r| Session {
            id:          r.get("id"),
            user_id:     r.get("user_id"),
            token_hash:  r.get("token_hash"),
            device_info: r.get::<serde_json::Value, _>("device_info"),
            ip_address:  r.get("ip_address"),
            org_id:      r.get("org_id"),
            expires_at:  r.get("expires_at"),
            created_at:  r.get("created_at"),
        }).collect())
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
}

// ── CredentialRepository ──────────────────────────────────────────────────────

#[async_trait]
impl CredentialRepository for PostgresStore {
    async fn create(&self, data: CreateCredential) -> Result<Credential> {
        let kind_str = credential_kind_str(&data.kind);
        let meta     = data.metadata.unwrap_or(serde_json::Value::Null);

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
            id:              row.get("id"),
            user_id:         row.get("user_id"),
            kind:            credential_kind_from_str(row.get("kind")),
            credential_hash: row.get("credential_hash"),
            metadata:        row.get::<serde_json::Value, _>("metadata"),
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
            id:              r.get("id"),
            user_id:         r.get("user_id"),
            kind:            credential_kind_from_str(r.get("kind")),
            credential_hash: r.get("credential_hash"),
            metadata:        r.get::<serde_json::Value, _>("metadata"),
        }))
    }

    async fn delete_by_user_and_kind(&self, user_id: Uuid, kind: CredentialKind) -> Result<()> {
        let result = sqlx::query(
            "DELETE FROM authx_credentials WHERE user_id = $1 AND kind = $2",
        )
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
                    return AuthError::Storage(StorageError::Conflict(
                        format!("slug '{}' already taken", data.slug),
                    ));
                }
            }
            db_err(e)
        })?;

        tracing::debug!(slug = %data.slug, "org row inserted");
        Ok(Organization {
            id:         row.get("id"),
            name:       row.get("name"),
            slug:       row.get("slug"),
            metadata:   row.get::<serde_json::Value, _>("metadata"),
            created_at: row.get("created_at"),
        })
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Organization>> {
        let row = sqlx::query(
            "SELECT id, name, slug, metadata, created_at FROM authx_orgs WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;

        Ok(row.map(|r| Organization {
            id:         r.get("id"),
            name:       r.get("name"),
            slug:       r.get("slug"),
            metadata:   r.get::<serde_json::Value, _>("metadata"),
            created_at: r.get("created_at"),
        }))
    }

    async fn find_by_slug(&self, slug: &str) -> Result<Option<Organization>> {
        let row = sqlx::query(
            "SELECT id, name, slug, metadata, created_at FROM authx_orgs WHERE slug = $1",
        )
        .bind(slug)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;

        Ok(row.map(|r| Organization {
            id:         r.get("id"),
            name:       r.get("name"),
            slug:       r.get("slug"),
            metadata:   r.get::<serde_json::Value, _>("metadata"),
            created_at: r.get("created_at"),
        }))
    }

    async fn add_member(&self, org_id: Uuid, user_id: Uuid, role_id: Uuid) -> Result<Membership> {
        // Fetch the role first.
        let role_row = sqlx::query(
            "SELECT id, org_id, name, permissions FROM authx_roles WHERE id = $1",
        )
        .bind(role_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?
        .ok_or(AuthError::Storage(StorageError::NotFound))?;

        let role = Role {
            id:          role_row.get("id"),
            org_id:      role_row.get("org_id"),
            name:        role_row.get("name"),
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
            id:         row.get("id"),
            user_id:    row.get("user_id"),
            org_id:     row.get("org_id"),
            role,
            created_at: row.get("created_at"),
        })
    }

    async fn remove_member(&self, org_id: Uuid, user_id: Uuid) -> Result<()> {
        let result = sqlx::query(
            "DELETE FROM authx_memberships WHERE org_id = $1 AND user_id = $2",
        )
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

        Ok(rows.into_iter().map(|r| Membership {
            id:      r.get("id"),
            user_id: r.get("user_id"),
            org_id:  r.get("org_id"),
            role: Role {
                id:          r.get("role_id"),
                org_id:      r.get("role_org_id"),
                name:        r.get("role_name"),
                permissions: r.get::<Vec<String>, _>("permissions"),
            },
            created_at: r.get("created_at"),
        }).collect())
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
        Ok(AuditLog {
            id:            row.get("id"),
            user_id:       row.get("user_id"),
            org_id:        row.get("org_id"),
            action:        row.get("action"),
            resource_type: row.get("resource_type"),
            resource_id:   row.get("resource_id"),
            ip_address:    row.get("ip_address"),
            metadata:      row.get::<serde_json::Value, _>("metadata"),
            created_at:    row.get("created_at"),
        })
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

        Ok(rows.into_iter().map(|r| AuditLog {
            id:            r.get("id"),
            user_id:       r.get("user_id"),
            org_id:        r.get("org_id"),
            action:        r.get("action"),
            resource_type: r.get("resource_type"),
            resource_id:   r.get("resource_id"),
            ip_address:    r.get("ip_address"),
            metadata:      r.get::<serde_json::Value, _>("metadata"),
            created_at:    r.get("created_at"),
        }).collect())
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

        Ok(rows.into_iter().map(|r| AuditLog {
            id:            r.get("id"),
            user_id:       r.get("user_id"),
            org_id:        r.get("org_id"),
            action:        r.get("action"),
            resource_type: r.get("resource_type"),
            resource_id:   r.get("resource_id"),
            ip_address:    r.get("ip_address"),
            metadata:      r.get::<serde_json::Value, _>("metadata"),
            created_at:    r.get("created_at"),
        }).collect())
    }
}
