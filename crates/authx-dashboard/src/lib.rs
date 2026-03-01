//! authx-dashboard — embedded admin dashboard (HTMX-powered)
//!
//! # Mounting
//! ```ignore
//! use authx_dashboard::DashboardState;
//!
//! let dashboard = DashboardState::new(store.clone(), events.clone(), 86400);
//! let app = Router::new()
//!     .nest("/_authx", dashboard.router("my-secret-admin-token"));
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
use authx_storage::ports::{AuditLogRepository, OrgRepository, SessionRepository, UserRepository};
use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    Router,
};

/// Shared state threaded through every dashboard route.
#[derive(Clone)]
pub struct DashboardState<S> {
    pub(crate) admin: Arc<AdminService<S>>,
    pub(crate) token: Arc<String>,
}

impl<S> DashboardState<S>
where
    S: UserRepository
        + SessionRepository
        + OrgRepository
        + AuditLogRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    pub fn new(storage: S, events: EventBus, session_ttl_secs: i64) -> Self {
        Self {
            admin: Arc::new(AdminService::new(storage, events, session_ttl_secs)),
            token: Arc::new(String::new()),
        }
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

    if provided.is_empty() || provided != state.token.as_str() {
        tracing::warn!("dashboard: rejected request — invalid or missing admin token");
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(req).await)
}
