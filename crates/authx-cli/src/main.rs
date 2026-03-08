mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(
    name = "authx",
    version,
    about = "authx-rs — authentication framework CLI",
    long_about = "Manage an authx server: run migrations, start the HTTP server, and administer users & API keys."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize an authx project scaffold.
    Init(commands::init::InitArgs),

    /// Seed demo data (admin user, org, OIDC client).
    Seed(commands::seed::SeedArgs),

    /// Start the authx HTTP server.
    Serve(commands::serve::ServeArgs),

    /// Run pending database migrations.
    Migrate(commands::migrate::MigrateArgs),

    /// Manage users.
    #[command(subcommand)]
    User(commands::user::UserCommand),

    /// Manage API keys.
    #[command(subcommand)]
    Key(commands::key::KeyCommand),

    /// Manage OIDC clients and federation providers.
    #[command(subcommand)]
    Oidc(commands::oidc::OidcCommand),
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,authx=debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Init(args) => commands::init::run(args).await,
        Command::Seed(args) => commands::seed::run(args).await,
        Command::Serve(args) => commands::serve::run(args).await,
        Command::Migrate(args) => commands::migrate::run(args).await,
        Command::User(cmd) => commands::user::run(cmd).await,
        Command::Key(cmd) => commands::key::run(cmd).await,
        Command::Oidc(cmd) => commands::oidc::run(cmd).await,
    }
}
