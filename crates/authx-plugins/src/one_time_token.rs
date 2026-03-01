/// Shared single-use token infrastructure.
///
/// Tokens are:
/// - 32 random bytes → hex encoded (64 chars)
/// - SHA-256 hashed before storage (stored hash, raw returned to caller)
/// - Single-use (consumed on first successful verification)
/// - TTL-scoped
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use authx_core::crypto::sha256_hex;
use rand::Rng;

#[derive(Clone)]
struct TokenRecord {
    kind:       TokenKind,
    user_id:    uuid::Uuid,
    expires_at: Instant,
}

#[derive(Clone, PartialEq, Eq)]
pub enum TokenKind {
    PasswordReset,
    MagicLink,
    EmailVerification,
    EmailOtp,
}

/// In-memory single-use token store (no DB dependency — swap for Redis for
/// multi-instance deployments).
#[derive(Clone)]
pub struct OneTimeTokenStore {
    inner: Arc<Mutex<HashMap<String, TokenRecord>>>,
    ttl:   Duration,
}

impl OneTimeTokenStore {
    pub fn new(ttl: Duration) -> Self {
        Self { inner: Arc::new(Mutex::new(HashMap::new())), ttl }
    }

    pub fn issue(&self, user_id: uuid::Uuid, kind: TokenKind) -> String {
        let raw:  [u8; 32] = rand::thread_rng().gen();
        let token  = hex::encode(raw);
        let hash   = sha256_hex(token.as_bytes());

        let record = TokenRecord {
            kind,
            user_id,
            expires_at: Instant::now() + self.ttl,
        };

        let mut map = self.inner.lock().expect("token store lock poisoned");
        let now = Instant::now();
        map.retain(|_, r| r.expires_at > now);
        map.insert(hash, record);

        tracing::debug!(user_id = %user_id, "one-time token issued");
        token
    }

    pub fn consume(
        &self,
        raw_token: &str,
        expected_kind: TokenKind,
    ) -> Option<uuid::Uuid> {
        let hash = sha256_hex(raw_token.as_bytes());
        let mut map = self.inner.lock().expect("token store lock poisoned");

        let record = map.remove(&hash)?;

        if record.kind != expected_kind {
            map.insert(hash, record);
            return None;
        }

        if record.expires_at < Instant::now() {
            tracing::debug!("one-time token expired");
            return None;
        }

        tracing::debug!(user_id = %record.user_id, "one-time token consumed");
        Some(record.user_id)
    }
}
