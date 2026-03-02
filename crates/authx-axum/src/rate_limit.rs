use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;
use tower::{Layer, Service};

// ── Config ────────────────────────────────────────────────────────────────────

/// Rate-limit configuration: sliding window per IP.
#[derive(Clone)]
pub struct RateLimitConfig {
    /// Maximum requests allowed within `window`.
    pub max_requests: u32,
    /// Window duration.
    pub window: Duration,
}

impl RateLimitConfig {
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            max_requests,
            window,
        }
    }
}

// ── Shared state ──────────────────────────────────────────────────────────────

#[derive(Clone)]
struct RateLimitStore {
    // IP → (window_start, count_in_window)
    inner: Arc<Mutex<HashMap<IpAddr, (Instant, u32)>>>,
}

impl RateLimitStore {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns `true` if the request is allowed, `false` if it should be rejected.
    fn check(&self, ip: IpAddr, cfg: &RateLimitConfig) -> bool {
        let now = Instant::now();
        let mut map = match self.inner.lock() { Ok(g) => g, Err(e) => { tracing::error!("rate-limit mutex poisoned — recovering"); e.into_inner() } };

        let entry = map.entry(ip).or_insert((now, 0));

        if now.duration_since(entry.0) >= cfg.window {
            // New window: reset.
            *entry = (now, 1);
            true
        } else {
            entry.1 += 1;
            entry.1 <= cfg.max_requests
        }
    }
}

// ── Tower Layer ───────────────────────────────────────────────────────────────

/// Tower [`Layer`] that enforces a sliding-window rate limit per client IP.
///
/// The IP is read from (in order):
/// 1. `X-Forwarded-For` header (first entry)
/// 2. `X-Real-IP` header
/// 3. Connection peer address via [`axum::extract::ConnectInfo`] extension
///
/// Requests that cannot be attributed to an IP are always allowed through.
///
/// ```rust,ignore
/// let app = Router::new()
///     .route("/auth/sign-in", post(sign_in))
///     .layer(RateLimitLayer::new(
///         RateLimitConfig::new(10, Duration::from_secs(60))
///     ));
/// ```
#[derive(Clone)]
pub struct RateLimitLayer {
    config: RateLimitConfig,
    store: RateLimitStore,
}

impl RateLimitLayer {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            store: RateLimitStore::new(),
        }
    }
}

impl<Svc> Layer<Svc> for RateLimitLayer {
    type Service = RateLimitService<Svc>;

    fn layer(&self, inner: Svc) -> Self::Service {
        RateLimitService {
            config: self.config.clone(),
            store: self.store.clone(),
            inner,
        }
    }
}

// ── Tower Service ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct RateLimitService<Svc> {
    config: RateLimitConfig,
    store: RateLimitStore,
    inner: Svc,
}

impl<Svc, ReqBody> Service<axum::http::Request<ReqBody>> for RateLimitService<Svc>
where
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

    fn call(&mut self, req: axum::http::Request<ReqBody>) -> Self::Future {
        let config = self.config.clone();
        let store = self.store.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            if let Some(ip) = extract_ip(&req) {
                if !store.check(ip, &config) {
                    tracing::warn!(ip = %ip, "rate limit exceeded");
                    let body = Json(json!({
                        "error":   "rate_limit_exceeded",
                        "message": "too many requests — please slow down",
                    }));
                    return Ok((StatusCode::TOO_MANY_REQUESTS, body).into_response());
                }
            }

            inner.call(req).await
        })
    }
}

// ── IP extraction ─────────────────────────────────────────────────────────────

fn extract_ip<B>(req: &axum::http::Request<B>) -> Option<IpAddr> {
    // X-Forwarded-For: client, proxy1, proxy2 — take the leftmost (real client).
    if let Some(ip) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return Some(ip);
    }

    // X-Real-IP (nginx single-IP header).
    if let Some(ip) = req
        .headers()
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return Some(ip);
    }

    // ConnectInfo extension set by axum::serve with into_make_service_with_connect_info.
    req.extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, str::FromStr, time::Duration};

    use super::{RateLimitConfig, RateLimitStore};

    fn store() -> RateLimitStore {
        RateLimitStore::new()
    }
    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    #[test]
    fn allows_up_to_max_requests() {
        let s = store();
        let cfg = RateLimitConfig::new(3, Duration::from_secs(60));
        let a = ip("1.2.3.4");
        for _ in 0..3 {
            assert!(s.check(a, &cfg));
        }
    }

    #[test]
    fn rejects_after_max_requests() {
        let s = store();
        let cfg = RateLimitConfig::new(3, Duration::from_secs(60));
        let a = ip("5.6.7.8");
        for _ in 0..3 {
            s.check(a, &cfg);
        }
        assert!(!s.check(a, &cfg), "4th request must be rejected");
    }

    #[test]
    fn different_ips_are_independent() {
        let s = store();
        let cfg = RateLimitConfig::new(2, Duration::from_secs(60));
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");

        s.check(a, &cfg);
        s.check(a, &cfg);
        assert!(!s.check(a, &cfg), "a should be rate-limited");
        assert!(s.check(b, &cfg), "b is independent");
    }

    #[test]
    fn window_expiry_resets_counter() {
        let s = store();
        // 50 ms window — reliably shorter than the sleep below.
        let cfg = RateLimitConfig::new(1, Duration::from_millis(50));
        let a = ip("9.9.9.9");

        s.check(a, &cfg); // consume quota
        assert!(!s.check(a, &cfg), "should be rejected inside window");

        std::thread::sleep(Duration::from_millis(60));

        assert!(s.check(a, &cfg), "new window should allow request");
    }
}
