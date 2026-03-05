use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use authx_core::crypto::sha256_hex;
use authx_core::models::{CreateOidcClient, CreateOidcFederationProvider};
use authx_storage::{
    memory::MemoryStore,
    ports::{DeviceCodeRepository, OidcClientRepository, OidcFederationProviderRepository},
};

#[derive(Subcommand)]
pub enum OidcCommand {
    /// Manage OIDC clients (authx as provider).
    #[command(subcommand)]
    Client(ClientCommand),

    /// Manage OIDC federation providers (external IdPs).
    #[command(subcommand)]
    Federation(FederationCommand),

    /// Manage device authorization codes (RFC 8628).
    #[command(subcommand)]
    Device(DeviceCommand),
}

// ── Clients ────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum ClientCommand {
    /// List OIDC clients (in-memory store only — demo tooling).
    List(ClientListArgs),

    /// Create a new OIDC client.
    Create(ClientCreateArgs),
}

#[derive(Args)]
pub struct ClientListArgs {
    /// Number of clients to show.
    #[arg(long, default_value_t = 50)]
    limit: u32,

    /// Number of clients to skip.
    #[arg(long, default_value_t = 0)]
    offset: u32,
}

#[derive(Args)]
pub struct ClientCreateArgs {
    /// Human-readable name for this client.
    pub name: String,

    /// Comma-separated redirect URIs.
    #[arg(long)]
    pub redirect_uris: String,

    /// Space-separated scopes (default: "openid profile email").
    #[arg(long, default_value = "openid profile email")]
    pub scopes: String,

    /// Optional client secret (confidential clients). Omit for public clients.
    #[arg(long)]
    pub client_secret: Option<String>,
}

// ── Federation providers ───────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum FederationCommand {
    /// List configured OIDC federation providers.
    List(FederationListArgs),

    /// Create a new OIDC federation provider.
    ///
    /// NOTE: You must pass the same AES-256 key (hex) that your server uses
    /// for encrypting OAuth tokens and client secrets.
    Create(FederationCreateArgs),
}

#[derive(Args)]
pub struct FederationListArgs;

#[derive(Args)]
pub struct FederationCreateArgs {
    /// Provider name (e.g. "okta-acme", used in URLs).
    pub name: String,

    /// OIDC issuer URL (e.g. https://acme.okta.com).
    pub issuer: String,

    /// OAuth2 client_id issued by the IdP.
    pub client_id: String,

    /// OAuth2 client_secret issued by the IdP.
    pub client_secret: String,

    /// Space-separated scopes (default: "openid profile email").
    #[arg(long, default_value = "openid profile email")]
    pub scopes: String,

    /// 64-hex-character AES-256 key used by your server (same as OIDC federation service).
    #[arg(long, value_name = "HEX_KEY")]
    pub enc_key_hex: String,
}

// ── Device codes ──────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum DeviceCommand {
    /// List pending device codes for a given client_id.
    List(DeviceListArgs),
}

#[derive(Args)]
pub struct DeviceListArgs {
    /// The client_id to filter device codes by.
    pub client_id: String,

    #[arg(long, default_value_t = 50)]
    limit: u32,

    #[arg(long, default_value_t = 0)]
    offset: u32,
}

// ── Entrypoint ─────────────────────────────────────────────────────────────────

pub async fn run(cmd: OidcCommand) -> Result<()> {
    match cmd {
        OidcCommand::Client(sub) => match sub {
            ClientCommand::List(args) => list_clients(args).await,
            ClientCommand::Create(args) => create_client(args).await,
        },
        OidcCommand::Federation(sub) => match sub {
            FederationCommand::List(args) => list_federation(args).await,
            FederationCommand::Create(args) => create_federation(args).await,
        },
        OidcCommand::Device(sub) => match sub {
            DeviceCommand::List(args) => list_device_codes(args).await,
        },
    }
}

async fn list_clients(args: ClientListArgs) -> Result<()> {
    let store = MemoryStore::new();
    let clients = OidcClientRepository::list(&store, args.offset, args.limit)
        .await
        .context("list clients")?;

    if clients.is_empty() {
        println!("No OIDC clients found.");
        return Ok(());
    }

    println!("{:<38} {:<32} {}", "ID", "Client ID", "Name");
    println!("{}", "-".repeat(90));
    for c in &clients {
        println!("{:<38} {:<32} {}", c.id, c.client_id, c.name);
    }
    println!("\n{} client(s) shown.", clients.len());
    Ok(())
}

async fn create_client(args: ClientCreateArgs) -> Result<()> {
    let store = MemoryStore::new();

    let redirect_uris: Vec<String> = args
        .redirect_uris
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    if redirect_uris.is_empty() {
        anyhow::bail!("at least one redirect URI is required");
    }

    let secret_hash = args
        .client_secret
        .as_ref()
        .map(|s| sha256_hex(s.as_bytes()))
        .unwrap_or_default();

    let client = OidcClientRepository::create(
        &store,
        CreateOidcClient {
            name: args.name.clone(),
            redirect_uris,
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            response_types: vec!["code".into()],
            allowed_scopes: args.scopes.clone(),
            secret_hash,
        },
    )
    .await
    .context("create client")?;

    println!("OIDC client created:");
    println!("  ID:         {}", client.id);
    println!("  Client ID:  {}", client.client_id);
    println!("  Name:       {}", client.name);
    println!("  Redirects:  {}", client.redirect_uris.join(", "));
    println!("  Scopes:     {}", client.allowed_scopes);
    if args.client_secret.is_some() {
        println!("  Type:       confidential (secret hashed)");
    } else {
        println!("  Type:       public (no secret)");
    }
    Ok(())
}

async fn list_federation(_args: FederationListArgs) -> Result<()> {
    let store = MemoryStore::new();
    let providers = OidcFederationProviderRepository::list_enabled(&store)
        .await
        .context("list providers")?;

    if providers.is_empty() {
        println!("No federation providers found.");
        return Ok(());
    }

    println!("{:<38} {:<18} {:<40} {}", "ID", "Name", "Issuer", "Scopes");
    println!("{}", "-".repeat(110));
    for p in &providers {
        println!("{:<38} {:<18} {:<40} {}", p.id, p.name, p.issuer, p.scopes);
    }
    println!("\n{} provider(s) shown.", providers.len());
    Ok(())
}

async fn create_federation(args: FederationCreateArgs) -> Result<()> {
    let store = MemoryStore::new();

    let key_bytes = hex::decode(args.enc_key_hex.trim()).context("decode enc_key_hex")?;
    if key_bytes.len() != 32 {
        anyhow::bail!("enc_key_hex must decode to 32 bytes (AES-256 key)");
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    let secret_enc = authx_core::crypto::encrypt(&key, args.client_secret.as_bytes())
        .context("encrypt client_secret")?;

    let provider = OidcFederationProviderRepository::create(
        &store,
        CreateOidcFederationProvider {
            name: args.name.clone(),
            issuer: args.issuer.clone(),
            client_id: args.client_id.clone(),
            secret_enc,
            scopes: args.scopes.clone(),
        },
    )
    .await
    .context("create federation provider")?;

    println!("Federation provider created:");
    println!("  ID:      {}", provider.id);
    println!("  Name:    {}", provider.name);
    println!("  Issuer:  {}", provider.issuer);
    println!("  Scopes:  {}", provider.scopes);
    Ok(())
}

async fn list_device_codes(args: DeviceListArgs) -> Result<()> {
    let store = MemoryStore::new();
    let codes =
        DeviceCodeRepository::list_by_client(&store, &args.client_id, args.offset, args.limit)
            .await
            .context("list device codes")?;

    if codes.is_empty() {
        println!("No device codes found for client '{}'.", args.client_id);
        return Ok(());
    }

    println!(
        "{:<38} {:<12} {:<12} {:<12} {}",
        "ID", "User Code", "Authorized", "Denied", "Expires At"
    );
    println!("{}", "-".repeat(100));
    for dc in &codes {
        println!(
            "{:<38} {:<12} {:<12} {:<12} {}",
            dc.id, dc.user_code, dc.authorized, dc.denied, dc.expires_at
        );
    }
    println!("\n{} code(s) shown.", codes.len());
    Ok(())
}
