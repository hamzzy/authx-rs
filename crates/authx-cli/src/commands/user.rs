use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use authx_core::models::CreateUser;
use authx_storage::{memory::MemoryStore, ports::UserRepository};

#[derive(Subcommand)]
pub enum UserCommand {
    /// List users (in-memory store only — use your DB admin for postgres).
    List(ListArgs),

    /// Create a new user by email.
    Create(CreateArgs),
}

#[derive(Args)]
pub struct ListArgs {
    /// Number of users to show (max).
    #[arg(long, default_value_t = 20)]
    limit: u32,

    /// Number of users to skip.
    #[arg(long, default_value_t = 0)]
    offset: u32,
}

#[derive(Args)]
pub struct CreateArgs {
    /// User email address.
    email: String,

    /// Optional username.
    #[arg(long)]
    username: Option<String>,
}

pub async fn run(cmd: UserCommand) -> Result<()> {
    match cmd {
        UserCommand::List(args) => list(args).await,
        UserCommand::Create(args) => create(args).await,
    }
}

async fn list(args: ListArgs) -> Result<()> {
    let store = MemoryStore::new();
    let users = UserRepository::list(&store, args.offset, args.limit)
        .await
        .context("failed to list users")?;

    if users.is_empty() {
        tracing::info!("No users found.");
        return Ok(());
    }

    tracing::info!("{:<38} {:<32} Verified", "ID", "Email");
    tracing::info!("{}", "-".repeat(80));
    for u in &users {
        tracing::info!("{:<38} {:<32} {}", u.id, u.email, u.email_verified);
    }
    tracing::info!("{} user(s) shown.", users.len());
    Ok(())
}

async fn create(args: CreateArgs) -> Result<()> {
    let store = MemoryStore::new();
    let user = UserRepository::create(
        &store,
        CreateUser {
            email: args.email.clone(),
            username: args.username.clone(),
            metadata: None,
        },
    )
    .await
    .context("failed to create user")?;

    tracing::info!("Created user:");
    tracing::info!("  ID:       {}", user.id);
    tracing::info!("  Email:    {}", user.email);
    if let Some(ref uname) = user.username {
        tracing::info!("  Username: {}", uname);
    }
    Ok(())
}
