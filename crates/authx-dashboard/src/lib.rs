//! authx-dashboard — embedded admin dashboard (HTMX-powered)
//!
//! # Mounting
//! ```ignore
//! use authx_dashboard::DashboardState;
//!
//! let dashboard = DashboardState::new(store.clone(), events.clone(), 86400);
//! let app = Router::new()
//!     .nest("/_authx", dashboard.router("my-secret-admin-token"));
//!
//! // For federation provider secret encryption:
//! // export AUTHX_ENCRYPTION_KEY="$(openssl rand -hex 32)"
//! ```
//!
//! All API routes require `Authorization: Bearer <admin_token>`.
//! The UI page itself is served without authentication so the login form can
//! be presented; the embedded JS stores the token in sessionStorage.

mod api;
mod html;

use std::sync::Arc;

use authx_core::events::EventBus;
use authx_plugins::AdminService;
use authx_storage::ports::{
    AuditLogRepository, DeviceCodeRepository, OidcClientRepository,
    OidcFederationProviderRepository, OrgRepository, SessionRepository, UserRepository,
};
use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    Router,
};
use subtle::ConstantTimeEq;

/// Shared state threaded through every dashboard route.
#[derive(Clone)]
pub struct DashboardState<S> {
    pub(crate) admin: Arc<AdminService<S>>,
    pub(crate) token: Arc<String>,
    pub(crate) encryption_key: Option<[u8; 32]>,
}

impl<S> DashboardState<S>
where
    S: UserRepository
        + SessionRepository
        + OrgRepository
        + AuditLogRepository
        + OidcClientRepository
        + OidcFederationProviderRepository
        + DeviceCodeRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    pub fn new(storage: S, events: EventBus, session_ttl_secs: i64) -> Self {
        let encryption_key = match authx_core::crypto::encryption_key_from_env(
            "AUTHX_ENCRYPTION_KEY",
        ) {
            Ok(key) => Some(key),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "dashboard: AUTHX_ENCRYPTION_KEY missing/invalid; federation secrets cannot be created"
                );
                None
            }
        };
        Self {
            admin: Arc::new(AdminService::new(storage, events, session_ttl_secs)),
            token: Arc::new(String::new()),
            encryption_key,
        }
    }

    /// Explicitly set the encryption key used for OIDC federation secret storage.
    pub fn with_encryption_key(mut self, key: [u8; 32]) -> Self {
        self.encryption_key = Some(key);
        self
    }

    /// Build the dashboard [`Router`].
    pub fn router(mut self, admin_token: impl Into<String>) -> Router {
        self.token = Arc::new(admin_token.into());

        let state = self.clone();

        Router::new()
            .merge(html::routes())
            .nest("/api", api::routes::<S>().with_state(self))
            .layer(middleware::from_fn_with_state(state, bearer_auth::<S>))
    }
}

async fn bearer_auth<S>(
    State(state): State<DashboardState<S>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode>
where
    S: Clone + Send + Sync + 'static,
{
    // The root HTML page is always served — JS handles the auth token prompt.
    if req.uri().path() == "/" {
        return Ok(next.run(req).await);
    }

    let provided = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");

    let token_bytes = state.token.as_bytes();
    let valid = !provided.is_empty()
        && provided.len() == token_bytes.len()
        && provided.as_bytes().ct_eq(token_bytes).unwrap_u8() == 1;

    if !valid {
        tracing::warn!("dashboard: rejected request — invalid or missing admin token");
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(req).await)
}
