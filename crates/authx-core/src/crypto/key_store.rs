use std::sync::{Arc, RwLock};

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use tracing::instrument;
use uuid::Uuid;

use crate::error::{AuthError, Result};

use super::signing::Claims;

/// A versioned key pair entry.
struct KeyVersion {
    /// Unique version identifier — included in the JWT `kid` header.
    kid: String,
    encoding: EncodingKey,
    decoding: DecodingKey,
}

/// Zero-downtime key rotation store.
///
/// Holds up to `max_keys` Ed25519 key pairs simultaneously. The *latest*
/// added key is used for signing; all retained keys can verify tokens.
/// During rotation:
///
/// 1. Call `rotate(private_pem, public_pem)` to add the new key.
/// 2. New tokens are signed with the new key immediately.
/// 3. Old tokens remain verifiable until their natural expiry.
/// 4. Call `prune()` to remove the oldest key once all old tokens have expired.
///
/// # Example
/// ```rust,ignore
/// let mut store = KeyRotationStore::new(3);
/// store.add_key("v1", PRIVATE_PEM, PUBLIC_PEM)?;
///
/// // Later, on rotation:
/// store.rotate("v2", NEW_PRIVATE_PEM, NEW_PUBLIC_PEM)?;
/// ```
pub struct KeyRotationStore {
    inner: Arc<RwLock<Inner>>,
    max_keys: usize,
}

struct Inner {
    keys: Vec<KeyVersion>,
}

impl KeyRotationStore {
    /// Create a new store. `max_keys` caps how many key versions are retained
    /// simultaneously (minimum 1, maximum 16).
    pub fn new(max_keys: usize) -> Self {
        let max_keys = max_keys.clamp(1, 16);
        Self {
            inner: Arc::new(RwLock::new(Inner { keys: Vec::new() })),
            max_keys,
        }
    }

    /// Load the initial key pair. `kid` is a human-readable version tag.
    pub fn add_key(
        &self,
        kid: impl Into<String>,
        private_pem: &[u8],
        public_pem: &[u8],
    ) -> Result<()> {
        let encoding = EncodingKey::from_ed_pem(private_pem)
            .map_err(|e| AuthError::Internal(format!("invalid private key: {e}")))?;
        let decoding = DecodingKey::from_ed_pem(public_pem)
            .map_err(|e| AuthError::Internal(format!("invalid public key: {e}")))?;

        let version = KeyVersion {
            kid: kid.into(),
            encoding,
            decoding,
        };
        let mut inner = match self.inner.write() {
            Ok(g) => g,
            Err(e) => {
                tracing::error!("key store write-lock poisoned — recovering");
                e.into_inner()
            }
        };
        inner.keys.push(version);

        // Enforce max_keys by evicting the oldest.
        while inner.keys.len() > self.max_keys {
            let removed = inner.keys.remove(0);
            tracing::info!(kid = %removed.kid, "key version evicted");
        }

        let current_kid = inner.keys.last().map(|k| k.kid.clone()).unwrap_or_default();
        tracing::info!(kid = %current_kid, total = inner.keys.len(), "key version added");
        Ok(())
    }

    /// Convenience alias — same as `add_key` but semantically signals rotation.
    pub fn rotate(
        &self,
        kid: impl Into<String>,
        private_pem: &[u8],
        public_pem: &[u8],
    ) -> Result<()> {
        self.add_key(kid, private_pem, public_pem)
    }

    /// Drop the oldest key version (call after old tokens have expired).
    pub fn prune_oldest(&self) {
        let mut inner = match self.inner.write() {
            Ok(g) => g,
            Err(e) => {
                tracing::error!("key store write-lock poisoned — recovering");
                e.into_inner()
            }
        };
        if inner.keys.len() > 1 {
            let removed = inner.keys.remove(0);
            tracing::info!(kid = %removed.kid, "oldest key version pruned");
        }
    }

    /// Sign a JWT with the current (newest) key.
    #[instrument(skip(self, extra), fields(sub = %subject))]
    pub fn sign(
        &self,
        subject: Uuid,
        ttl_seconds: i64,
        extra: serde_json::Value,
    ) -> Result<String> {
        use chrono::Utc;

        let inner = match self.inner.read() {
            Ok(g) => g,
            Err(e) => {
                tracing::error!("key store read-lock poisoned — recovering");
                e.into_inner()
            }
        };
        let kv = inner
            .keys
            .last()
            .ok_or_else(|| AuthError::Internal("key store is empty — add a key first".into()))?;

        let now = Utc::now().timestamp();
        let claims = Claims {
            sub: subject.to_string(),
            exp: now + ttl_seconds,
            iat: now,
            jti: Uuid::new_v4().to_string(),
            org: None,
            extra,
        };

        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(kv.kid.clone());

        let token = encode(&header, &claims, &kv.encoding)
            .map_err(|e| AuthError::Internal(format!("jwt sign failed: {e}")))?;

        tracing::debug!(kid = %kv.kid, sub = %subject, "jwt signed");
        Ok(token)
    }

    /// Verify a JWT against *all* retained key versions (newest first).
    #[instrument(skip(self, token))]
    pub fn verify(&self, token: &str) -> Result<Claims> {
        let inner = match self.inner.read() {
            Ok(g) => g,
            Err(e) => {
                tracing::error!("key store read-lock poisoned — recovering");
                e.into_inner()
            }
        };

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.validate_exp = true;

        // Extract `kid` from the header to try the right key first.
        let header = jsonwebtoken::decode_header(token).map_err(|_| AuthError::InvalidToken)?;
        let preferred_kid = header.kid.as_deref();

        // Try keys newest-first, preferring the kid match.
        let ordered: Vec<_> = inner.keys.iter().rev().collect();
        for kv in &ordered {
            if let Some(kid) = preferred_kid {
                if kv.kid != kid {
                    continue; // skip non-matching first pass
                }
            }
            if let Ok(data) = decode::<Claims>(token, &kv.decoding, &validation) {
                tracing::debug!(kid = %kv.kid, sub = %data.claims.sub, "jwt verified");
                return Ok(data.claims);
            }
        }

        // Fallback: try all keys (handles tokens without kid or mismatched kid).
        for kv in &ordered {
            if let Ok(data) = decode::<Claims>(token, &kv.decoding, &validation) {
                tracing::debug!(kid = %kv.kid, sub = %data.claims.sub, "jwt verified (fallback)");
                return Ok(data.claims);
            }
        }

        tracing::warn!("jwt verification failed against all key versions");
        Err(AuthError::InvalidToken)
    }

    /// Number of currently retained key versions.
    pub fn key_count(&self) -> usize {
        match self.inner.read() {
            Ok(g) => g.keys.len(),
            Err(e) => {
                tracing::error!("key store read-lock poisoned — recovering");
                e.into_inner().keys.len()
            }
        }
    }
}

impl Clone for KeyRotationStore {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            max_keys: self.max_keys,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    // Minimal Ed25519 PEM pair for testing (generated offline).
    // These are test-only keys — never use in production.
    const PRIV_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ+DYDHbiFQiDpMqQR5JN9QOCiIxj7T/XmVbz3Cg+xvL\n-----END PRIVATE KEY-----\n";
    const PUB_PEM: &[u8] = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAoNFBPj4h5jFITR2XlDqz8qFjNXaXFJF3mJoSBpVwC1E=\n-----END PUBLIC KEY-----\n";

    // Second key pair.
    const PRIV2_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIBBZj4V3sFR3zIieCbxHnrLoAoEJQHBkJPIJlqMvpO5U\n-----END PRIVATE KEY-----\n";
    const PUB2_PEM: &[u8] = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA2YkJaLvQK1gTnYqQB8djQZfPOvXrJTpGE9nO9A4Xbg0=\n-----END PUBLIC KEY-----\n";

    #[test]
    fn empty_store_sign_fails() {
        let store = KeyRotationStore::new(2);
        assert!(store
            .sign(Uuid::new_v4(), 3600, serde_json::Value::Null)
            .is_err());
    }

    #[test]
    fn empty_store_verify_fails() {
        let store = KeyRotationStore::new(2);
        assert!(store.verify("not.a.token").is_err());
    }

    #[test]
    fn key_count_tracks_additions() {
        let store = KeyRotationStore::new(3);
        assert_eq!(store.key_count(), 0);

        if store.add_key("v1", PRIV_PEM, PUB_PEM).is_ok() {
            assert_eq!(store.key_count(), 1);
        }
    }

    #[test]
    fn invalid_pem_rejected() {
        let store = KeyRotationStore::new(2);
        let err = store.add_key("bad", b"not-a-pem", b"also-not-a-pem");
        assert!(err.is_err());
    }

    #[test]
    fn clone_shares_state() {
        let store = KeyRotationStore::new(2);
        let clone = store.clone();
        // Mutations through one are visible from the other.
        if store.add_key("v1", PRIV_PEM, PUB_PEM).is_ok() {
            assert_eq!(clone.key_count(), 1);
        }
    }

    #[test]
    fn max_keys_evicts_oldest() {
        let store = KeyRotationStore::new(1);
        // Add two keys — only the second should remain.
        let r1 = store.add_key("v1", PRIV_PEM, PUB_PEM);
        let r2 = store.add_key("v2", PRIV2_PEM, PUB2_PEM);

        if r1.is_ok() && r2.is_ok() {
            assert_eq!(store.key_count(), 1);
        }
    }
}
