use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// In-memory brute-force / account lockout tracker.
///
/// Tracks consecutive failed sign-in attempts per key (typically an email
/// address). After `max_failures` failed attempts within `window`, the
/// account is considered locked until the window elapses.
///
/// Successful sign-ins reset the failure counter for that key.
///
/// The tracker is `Clone + Send + Sync` — share a single instance across the
/// application via `Arc` or embed it directly in service state.
#[derive(Clone)]
pub struct LoginAttemptTracker {
    inner: Arc<Mutex<HashMap<String, FailureRecord>>>,
    cfg: LockoutConfig,
}

#[derive(Clone, Copy)]
pub struct LockoutConfig {
    /// Maximum consecutive failures before locking.
    pub max_failures: u32,
    /// How long a lock (or the failure window) lasts.
    pub window: Duration,
}

impl LockoutConfig {
    pub fn new(max_failures: u32, window: Duration) -> Self {
        Self {
            max_failures,
            window,
        }
    }
}

struct FailureRecord {
    count: u32,
    window_start: Instant,
}

impl LoginAttemptTracker {
    pub fn new(cfg: LockoutConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            cfg,
        }
    }

    /// Returns `true` if the key is currently locked out.
    pub fn is_locked(&self, key: &str) -> bool {
        let now = Instant::now();
        let map = match self.inner.lock() { Ok(g) => g, Err(e) => { tracing::error!("lockout tracker mutex poisoned — recovering"); e.into_inner() } };
        match map.get(key) {
            None => false,
            Some(rec) => {
                if now.duration_since(rec.window_start) >= self.cfg.window {
                    false // window expired
                } else {
                    rec.count >= self.cfg.max_failures
                }
            }
        }
    }

    /// Record a failed attempt. Call this when credentials are wrong.
    pub fn record_failure(&self, key: &str) {
        let now = Instant::now();
        let mut map = match self.inner.lock() { Ok(g) => g, Err(e) => { tracing::error!("lockout tracker mutex poisoned — recovering"); e.into_inner() } };
        let rec = map.entry(key.to_owned()).or_insert(FailureRecord {
            count: 0,
            window_start: now,
        });

        if now.duration_since(rec.window_start) >= self.cfg.window {
            // New window — reset count.
            rec.window_start = now;
            rec.count = 1;
        } else {
            rec.count += 1;
        }

        tracing::warn!(
            key = key,
            failures = rec.count,
            "failed login attempt recorded"
        );
    }

    /// Reset the failure counter on successful sign-in.
    pub fn record_success(&self, key: &str) {
        let mut map = match self.inner.lock() { Ok(g) => g, Err(e) => { tracing::error!("lockout tracker mutex poisoned — recovering"); e.into_inner() } };
        map.remove(key);
        tracing::debug!(key = key, "login success — failure counter cleared");
    }
}
