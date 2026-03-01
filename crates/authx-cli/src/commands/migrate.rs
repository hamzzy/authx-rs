use anyhow::{Context, Result};
use clap::Args;

use authx_storage::sqlx::PostgresStore;

#[derive(Args)]
pub struct MigrateArgs {
    /// PostgreSQL connection URL.
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,
}

pub async fn run(args: MigrateArgs) -> Result<()> {
    tracing::info!("connecting to postgres");
    let store = PostgresStore::connect(&args.database_url)
        .await
        .context("failed to connect to database")?;

    tracing::info!("running migrations");
    PostgresStore::migrate(&store.pool)
        .await
        .context("migration failed")?;

    tracing::info!("migrations complete");
    println!("Migrations applied successfully.");
    Ok(())
}
