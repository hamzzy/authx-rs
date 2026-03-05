use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Args, Subcommand};
use uuid::Uuid;

use authx_plugins::ApiKeyService;
use authx_storage::memory::MemoryStore;

#[derive(Subcommand)]
pub enum KeyCommand {
    /// Generate a new API key for a user (printed once, store it safely).
    Generate(GenerateArgs),

    /// List API keys for a user.
    List(ListArgs),

    /// Revoke an API key.
    Revoke(RevokeArgs),
}

#[derive(Args)]
pub struct GenerateArgs {
    /// User ID to issue the key for.
    user_id: Uuid,

    /// Human-readable name for this key.
    #[arg(long, default_value = "cli-generated")]
    name: String,

    /// Comma-separated scopes (e.g. read,write).
    #[arg(long, default_value = "")]
    scopes: String,

    /// Key lifetime in days (1–365, default 90).
    #[arg(long, default_value_t = 90)]
    expires_days: u32,
}

#[derive(Args)]
pub struct ListArgs {
    /// User ID whose keys to list.
    user_id: Uuid,
}

#[derive(Args)]
pub struct RevokeArgs {
    /// User ID owning the key.
    user_id: Uuid,

    /// API key ID to revoke.
    key_id: Uuid,
}

pub async fn run(cmd: KeyCommand) -> Result<()> {
    match cmd {
        KeyCommand::Generate(args) => generate(args).await,
        KeyCommand::List(args) => list(args).await,
        KeyCommand::Revoke(args) => revoke(args).await,
    }
}

async fn generate(args: GenerateArgs) -> Result<()> {
    let store = MemoryStore::new();
    let svc = ApiKeyService::new(store);

    let scopes: Vec<String> = args
        .scopes
        .split(',')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    let expires_days = args.expires_days.clamp(1, 365);
    let expires_at = Utc::now() + chrono::Duration::days(expires_days as i64);

    let resp = svc
        .create(args.user_id, None, args.name.clone(), scopes, expires_at)
        .await
        .context("failed to generate key")?;

    tracing::info!("API key generated:");
    tracing::info!("  Key ID:  {}", resp.key.id);
    tracing::info!("  Prefix:  {}", resp.key.prefix);
    tracing::info!("  Name:    {}", resp.key.name);
    tracing::info!("  RAW KEY (shown once — save it now):");
    tracing::info!("  {}", resp.raw_key);
    Ok(())
}

async fn list(args: ListArgs) -> Result<()> {
    let store = MemoryStore::new();
    let svc = ApiKeyService::new(store);
    let keys = svc
        .list(args.user_id)
        .await
        .context("failed to list keys")?;

    if keys.is_empty() {
        tracing::info!("No API keys found for this user.");
        return Ok(());
    }

    tracing::info!("{:<38} {:<10} {:<24} Expires", "Key ID", "Prefix", "Name");
    tracing::info!("{}", "-".repeat(90));
    for k in &keys {
        let exp = k.expires_at.map_or("never".into(), |t| t.to_rfc3339());
        tracing::info!("{:<38} {:<10} {:<24} {}", k.id, k.prefix, k.name, exp);
    }
    Ok(())
}

async fn revoke(args: RevokeArgs) -> Result<()> {
    let store = MemoryStore::new();
    let svc = ApiKeyService::new(store);
    svc.revoke(args.user_id, args.key_id)
        .await
        .context("failed to revoke key")?;
    tracing::info!("API key {} revoked.", args.key_id);
    Ok(())
}
