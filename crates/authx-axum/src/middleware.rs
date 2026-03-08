use std::sync::Arc;

use axum::response::Response;
use tower::{Layer, Service};

use authx_core::{crypto::sha256_hex, identity::Identity};
use authx_storage::ports::{SessionRepository, UserRepository};

const SESSION_HEADER: &str = "x-authx-token";
const SESSION_COOKIE: &str = "authx_session";

// ── Public Layer ─────────────────────────────────────────────────────────────

/// Tower [`Layer`] that resolves session tokens into [`Identity`] extensions.
///
/// Add this to your router **after** all routes. Unauthenticated requests pass
/// through; use [`RequireAuth`] on individual routes to enforce auth.
///
/// ```rust,ignore
/// let app = Router::new()
///     .route("/me", get(me))
///     .layer(SessionLayer::new(store));
/// ```
#[derive(Clone)]
pub struct SessionLayer<S> {
    storage: Arc<S>,
}

impl<S> SessionLayer<S>
where
    S: SessionRepository + UserRepository + Clone + Send + Sync + 'static,
{
    pub fn new(storage: S) -> Self {
        Self {
            storage: Arc::new(storage),
        }
    }
}

impl<S, Svc> Layer<Svc> for SessionLayer<S>
where
    S: SessionRepository + UserRepository + Clone + Send + Sync + 'static,
{
    type Service = SessionService<S, Svc>;

    fn layer(&self, inner: Svc) -> Self::Service {
        SessionService {
            storage: Arc::clone(&self.storage),
            inner,
        }
    }
}

// ── Inner Service ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SessionService<S, Svc> {
    storage: Arc<S>,
    inner: Svc,
}

impl<S, Svc, ReqBody> Service<axum::http::Request<ReqBody>> for SessionService<S, Svc>
where
    S: SessionRepository + UserRepository + Clone + Send + Sync + 'static,
    Svc: Service<axum::http::Request<ReqBody>, Response = Response> + Clone + Send + 'static,
    Svc::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response;
    type Error = Svc::Error;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, Svc::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: axum::http::Request<ReqBody>) -> Self::Future {
        let storage = Arc::clone(&self.storage);
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let token_hash = extract_token(&req).map(|t| sha256_hex(t.as_bytes()));

            if let Some(hash) = token_hash
                && let Some(identity) = resolve_identity(&*storage, &hash).await {
                    req.extensions_mut().insert(identity);
                    tracing::debug!("identity resolved");
                }

            inner.call(req).await
        })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn resolve_identity<S>(storage: &S, token_hash: &str) -> Option<Identity>
where
    S: SessionRepository + UserRepository + Clone + Send + Sync + 'static,
{
    let session = storage.find_by_token_hash(token_hash).await.ok()??;
    if session.expires_at < chrono::Utc::now() {
        tracing::debug!(session_id = %session.id, "session expired");
        return None;
    }
    let user = storage.find_by_id(session.user_id).await.ok()??;
    Some(Identity::new(user, session))
}

fn extract_token<B>(request: &axum::http::Request<B>) -> Option<String> {
    if let Some(bearer) = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        return Some(bearer.to_owned());
    }

    if let Some(token) = request
        .headers()
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        return Some(token.to_owned());
    }

    let cookie_header = request
        .headers()
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())?;

    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{SESSION_COOKIE}=")) {
            return Some(value.to_owned());
        }
    }

    None
}
