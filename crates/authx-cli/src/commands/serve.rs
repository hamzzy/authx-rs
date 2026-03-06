use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use axum::{response::Json, routing::get, Router};
use clap::Args;
use tower_http::trace::TraceLayer;

use authx_axum::{
    csrf_middleware, webauthn_router, AuthxState, CsrfConfig, RateLimitConfig, RateLimitLayer,
    SessionLayer,
};
use authx_core::brute_force::LockoutConfig;
use authx_core::config::AuthxConfig;
use authx_plugins::WebAuthnService;
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
    #[arg(
        long,
        env = "AUTHX_TRUSTED_ORIGINS",
        default_value = "http://localhost:3000"
    )]
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

    /// WebAuthn relying party ID (typically your domain).
    #[arg(long, env = "AUTHX_WEBAUTHN_RP_ID", default_value = "localhost")]
    webauthn_rp_id: String,

    /// WebAuthn allowed origin.
    #[arg(
        long,
        env = "AUTHX_WEBAUTHN_RP_ORIGIN",
        default_value = "http://localhost:3000"
    )]
    webauthn_rp_origin: String,

    /// WebAuthn challenge TTL in seconds.
    #[arg(long, env = "AUTHX_WEBAUTHN_CHALLENGE_TTL", default_value_t = 600)]
    webauthn_challenge_ttl_secs: u64,
}

#[derive(Clone)]
struct AppBuildOptions<'a, S> {
    session_store: S,
    auth_store: S,
    origins: &'a [String],
    session_ttl_secs: i64,
    secure_cookies: bool,
    lockout: LockoutConfig,
    rate_limit: u32,
    webauthn_rp_id: &'a str,
    webauthn_rp_origin: &'a str,
    webauthn_challenge_ttl_secs: u64,
}

fn validate_args(args: &ServeArgs) -> Result<()> {
    if args.bind.is_empty() {
        anyhow::bail!("AUTHX_BIND must not be empty");
    }
    if args.session_ttl == 0 {
        anyhow::bail!("AUTHX_SESSION_TTL must be greater than zero");
    }
    if args.rate_limit == 0 {
        anyhow::bail!("AUTHX_RATE_LIMIT must be greater than zero");
    }
    if args.lockout_failures == 0 {
        anyhow::bail!("AUTHX_LOCKOUT_FAILURES must be greater than zero");
    }
    if args.lockout_minutes == 0 {
        anyhow::bail!("AUTHX_LOCKOUT_MINUTES must be greater than zero");
    }
    if args.webauthn_rp_id.trim().is_empty() {
        anyhow::bail!("AUTHX_WEBAUTHN_RP_ID must not be empty");
    }
    if args.webauthn_rp_origin.trim().is_empty() {
        anyhow::bail!("AUTHX_WEBAUTHN_RP_ORIGIN must not be empty");
    }
    if args.webauthn_challenge_ttl_secs == 0 {
        anyhow::bail!("AUTHX_WEBAUTHN_CHALLENGE_TTL must be greater than zero");
    }
    let origins_valid = args
        .trusted_origins
        .split(',')
        .any(|s| !s.trim().is_empty());
    if !origins_valid {
        anyhow::bail!("AUTHX_TRUSTED_ORIGINS must contain at least one origin");
    }
    Ok(())
}

impl From<&ServeArgs> for AuthxConfig {
    fn from(args: &ServeArgs) -> Self {
        Self {
            bind: args.bind.clone(),
            database_url: args.database_url.clone(),
            secure_cookies: args.secure_cookies,
            session_ttl_secs: args.session_ttl as i64,
            trusted_origins: args
                .trusted_origins
                .split(',')
                .map(|s| s.trim().to_owned())
                .collect(),
            rate_limit_max: args.rate_limit,
            rate_limit_window: Duration::from_secs(60),
            lockout_max_failures: args.lockout_failures,
            lockout_window: Duration::from_secs(args.lockout_minutes * 60),
            webauthn_rp_id: args.webauthn_rp_id.clone(),
            webauthn_rp_origin: args.webauthn_rp_origin.clone(),
            webauthn_challenge_ttl_secs: args.webauthn_challenge_ttl_secs,
            ..AuthxConfig::default()
        }
    }
}

pub async fn run(args: ServeArgs) -> Result<()> {
    validate_args(&args)?;
    let cfg = AuthxConfig::from(&args);
    tracing::debug!(
        bind = %cfg.bind,
        session_ttl = cfg.session_ttl_secs,
        rate_limit = cfg.rate_limit_max,
        lockout_failures = cfg.lockout_max_failures,
        "startup config validated"
    );

    let lockout = LockoutConfig::new(cfg.lockout_max_failures, cfg.lockout_window);

    if let Some(ref url) = cfg.database_url {
        tracing::info!("connecting to postgres at {url}");
        let store = PostgresStore::connect(url).await?;
        PostgresStore::migrate(&store.pool).await?;
        tracing::info!("migrations applied");

        let app = make_app(AppBuildOptions {
            session_store: store.clone(),
            auth_store: store,
            origins: &cfg.trusted_origins,
            session_ttl_secs: cfg.session_ttl_secs,
            secure_cookies: cfg.secure_cookies,
            lockout,
            rate_limit: cfg.rate_limit_max,
            webauthn_rp_id: &cfg.webauthn_rp_id,
            webauthn_rp_origin: &cfg.webauthn_rp_origin,
            webauthn_challenge_ttl_secs: cfg.webauthn_challenge_ttl_secs,
        })?;
        return listen(app, &cfg.bind).await;
    }

    tracing::warn!("no DATABASE_URL — using in-memory store (data is not persisted)");
    let store = MemoryStore::new();
    let app = make_app(AppBuildOptions {
        session_store: store.clone(),
        auth_store: store,
        origins: &cfg.trusted_origins,
        session_ttl_secs: cfg.session_ttl_secs,
        secure_cookies: cfg.secure_cookies,
        lockout,
        rate_limit: cfg.rate_limit_max,
        webauthn_rp_id: &cfg.webauthn_rp_id,
        webauthn_rp_origin: &cfg.webauthn_rp_origin,
        webauthn_challenge_ttl_secs: cfg.webauthn_challenge_ttl_secs,
    })?;
    listen(app, &cfg.bind).await
}

fn make_app<S>(options: AppBuildOptions<'_, S>) -> Result<Router>
where
    S: authx_storage::StorageAdapter + Clone + Send + Sync + 'static,
{
    use axum::middleware;

    let AppBuildOptions {
        session_store,
        auth_store,
        origins,
        session_ttl_secs,
        secure_cookies,
        lockout,
        rate_limit,
        webauthn_rp_id,
        webauthn_rp_origin,
        webauthn_challenge_ttl_secs,
    } = options;

    let csrf = CsrfConfig::new(origins.iter().map(|s| s.as_str()));
    let rl_layer = RateLimitLayer::new(RateLimitConfig::new(rate_limit, Duration::from_secs(60)));
    let state =
        AuthxState::new_with_lockout(auth_store, session_ttl_secs, secure_cookies, lockout);
    let webauthn_service = Arc::new(WebAuthnService::new(
        session_store.clone(),
        webauthn_rp_id.to_owned(),
        webauthn_rp_origin.to_owned(),
        Duration::from_secs(webauthn_challenge_ttl_secs),
        session_ttl_secs,
    )?);

    let auth_router = state
        .router()
        .layer(rl_layer)
        .route_layer(middleware::from_fn_with_state(csrf, csrf_middleware));

    let webauthn = webauthn_router(webauthn_service)
        .layer(RateLimitLayer::new(RateLimitConfig::new(
            rate_limit,
            Duration::from_secs(60),
        )))
        .route_layer(middleware::from_fn_with_state(
            CsrfConfig::new(origins.iter().map(|s| s.as_str())),
            csrf_middleware,
        ));

    Ok(Router::new()
        .route("/health", get(health))
        .nest("/auth", auth_router)
        .nest("/auth/webauthn", webauthn)
        .layer(SessionLayer::new(session_store))
        .layer(TraceLayer::new_for_http()))
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
