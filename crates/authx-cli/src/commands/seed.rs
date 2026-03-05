use anyhow::Result;
use clap::Args;

use authx_core::models::{CreateOidcClient, CreateOrg, CreateUser};
use authx_storage::ports::{OidcClientRepository, OrgRepository, UserRepository};
use authx_storage::{memory::MemoryStore, sqlx::PostgresStore};

#[derive(Args)]
pub struct SeedArgs {
    /// PostgreSQL connection URL. If omitted, seeds an in-memory store (for testing only).
    #[arg(long, env = "DATABASE_URL")]
    database_url: Option<String>,
}

pub async fn run(args: SeedArgs) -> Result<()> {
    if let Some(ref url) = args.database_url {
        tracing::info!("connecting to postgres at {url}");
        let store = PostgresStore::connect(url).await?;
        PostgresStore::migrate(&store.pool).await?;
        seed(&store).await
    } else {
        tracing::warn!("no DATABASE_URL — seeding in-memory store (data will not persist)");
        let store = MemoryStore::new();
        seed(&store).await
    }
}

async fn seed<S>(store: &S) -> Result<()>
where
    S: UserRepository + OrgRepository + OidcClientRepository,
{
    // ── Admin user ──────────────────────────────────────────────────────────
    let admin_email = "admin@example.com";
    let admin = match UserRepository::find_by_email(store, admin_email).await? {
        Some(u) => {
            tracing::info!("  admin user already exists: {}", u.id);
            u
        }
        None => {
            let u = UserRepository::create(
                store,
                CreateUser {
                    email: admin_email.to_string(),
                    username: Some("admin".into()),
                    metadata: None,
                },
            )
            .await?;
            tracing::info!("  created admin user: {} ({})", u.id, admin_email);
            u
        }
    };

    // ── Demo organization ───────────────────────────────────────────────────
    let org_slug = "demo";
    let org = match OrgRepository::find_by_slug(store, org_slug).await? {
        Some(o) => {
            tracing::info!("  org '{}' already exists: {}", org_slug, o.id);
            o
        }
        None => {
            let o = OrgRepository::create(
                store,
                CreateOrg {
                    name: "Demo Organization".into(),
                    slug: org_slug.into(),
                    metadata: None,
                },
            )
            .await?;
            tracing::info!("  created org '{}': {}", org_slug, o.id);
            o
        }
    };

    // Add admin as org member (with default role)
    let roles = OrgRepository::find_roles(store, org.id).await?;
    if let Some(role) = roles.first() {
        match OrgRepository::add_member(store, org.id, admin.id, role.id).await {
            Ok(m) => tracing::info!("  added admin to org '{}' as member: {}", org_slug, m.id),
            Err(_) => tracing::info!("  admin already a member of '{}'", org_slug),
        }
    }

    // ── Sample OIDC client ──────────────────────────────────────────────────
    let clients = OidcClientRepository::list(store, 0, 100).await?;
    let demo_client = clients.iter().find(|c| c.name == "demo-app");
    match demo_client {
        Some(c) => {
            tracing::info!("  OIDC client 'demo-app' already exists: {}", c.client_id);
        }
        None => {
            let secret = "demo-secret-change-me";
            let secret_hash = authx_core::crypto::sha256_hex(secret.as_bytes());
            let c = OidcClientRepository::create(
                store,
                CreateOidcClient {
                    name: "demo-app".into(),
                    redirect_uris: vec!["http://localhost:3000/callback".into()],
                    grant_types: vec![
                        "authorization_code".into(),
                        "refresh_token".into(),
                        "urn:ietf:params:oauth:grant-type:device_code".into(),
                    ],
                    response_types: vec!["code".into()],
                    allowed_scopes: "openid profile email".into(),
                    secret_hash,
                },
            )
            .await?;
            tracing::info!(
                "  created OIDC client 'demo-app': {} (secret: {})",
                c.client_id,
                secret
            );
        }
    }

    tracing::info!("Seed complete. Summary:");
    tracing::info!("  Admin:  {} ({})", admin.id, admin_email);
    tracing::info!("  Org:    {} ({})", org.id, org_slug);
    tracing::info!("  Client: demo-app (secret: demo-secret-change-me)");

    Ok(())
}
