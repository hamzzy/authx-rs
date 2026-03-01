use std::time::Duration;

use anyhow::Result;
use axum::{Router, routing::get, response::Json};
use clap::Args;
use tower_http::trace::TraceLayer;

use authx_axum::{
    csrf_middleware, AuthxState, CsrfConfig, RateLimitConfig, RateLimitLayer, SessionLayer,
};
use authx_core::brute_force::LockoutConfig;
use authx_storage::{memory::MemoryStore, sqlx::PostgresStore};

#[derive(Args)]
pub struct ServeArgs {
    /// Address to bind the server to.
    #[arg(long, env = "AUTHX_BIND", default_value = "0.0.0.0:3000")]
    bind: String,

    /// PostgreSQL connection URL. If omitted, an in-memory store is used.
    #[arg(long, env = "DATABASE_URL")]
    database_url: Option<String>,

    /// Comma-separated list of trusted origins for CSRF protection.
    #[arg(long, env = "AUTHX_TRUSTED_ORIGINS", default_value = "http://localhost:3000")]
    trusted_origins: String,

    /// Session TTL in seconds.
    #[arg(long, env = "AUTHX_SESSION_TTL", default_value_t = 60 * 60 * 24 * 30)]
    session_ttl: u64,

    /// Require HTTPS-only (Secure) cookies.
    #[arg(long, env = "AUTHX_SECURE_COOKIES", default_value_t = false)]
    secure_cookies: bool,

    /// Max auth requests per IP per minute.
    #[arg(long, env = "AUTHX_RATE_LIMIT", default_value_t = 30)]
    rate_limit: u32,

    /// Consecutive sign-in failures before account lockout.
    #[arg(long, env = "AUTHX_LOCKOUT_FAILURES", default_value_t = 5)]
    lockout_failures: u32,

    /// Lockout window in minutes.
    #[arg(long, env = "AUTHX_LOCKOUT_MINUTES", default_value_t = 15)]
    lockout_minutes: u64,
}

pub async fn run(args: ServeArgs) -> Result<()> {
    let origins: Vec<String> = args
        .trusted_origins
        .split(',')
        .map(|s| s.trim().to_owned())
        .collect();

    let lockout = LockoutConfig::new(
        args.lockout_failures,
        Duration::from_secs(args.lockout_minutes * 60),
    );

    if let Some(ref url) = args.database_url {
        tracing::info!("connecting to postgres at {url}");
        let store = PostgresStore::connect(url).await?;
        PostgresStore::migrate(&store.pool).await?;
        tracing::info!("migrations applied");

        let app = make_app(
            store.clone(), store,
            &origins, args.session_ttl, args.secure_cookies, lockout, args.rate_limit,
        );
        return listen(app, &args.bind).await;
    }

    tracing::warn!("no DATABASE_URL — using in-memory store (data is not persisted)");
    let store = MemoryStore::new();
    let app = make_app(
        store.clone(), store,
        &origins, args.session_ttl, args.secure_cookies, lockout, args.rate_limit,
    );
    listen(app, &args.bind).await
}

fn make_app<S>(
    session_store: S,
    auth_store:    S,
    origins:       &[String],
    session_ttl:   u64,
    secure:        bool,
    lockout:       LockoutConfig,
    rate_limit:    u32,
) -> Router
where
    S: authx_storage::StorageAdapter + Clone + Send + Sync + 'static,
{
    use axum::middleware;

    let csrf     = CsrfConfig::new(origins.iter().map(|s| s.as_str()));
    let rl_layer = RateLimitLayer::new(RateLimitConfig::new(rate_limit, Duration::from_secs(60)));
    let state    = AuthxState::new_with_lockout(auth_store, session_ttl as i64, secure, lockout);

    let auth_router = state
        .router()
        .layer(rl_layer)
        .route_layer(middleware::from_fn_with_state(csrf, csrf_middleware));

    Router::new()
        .route("/health", get(health))
        .nest("/auth", auth_router)
        .layer(SessionLayer::new(session_store))
        .layer(TraceLayer::new_for_http())
}

async fn listen(app: Router, bind: &str) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!("listening on http://{bind}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "authx" }))
}
