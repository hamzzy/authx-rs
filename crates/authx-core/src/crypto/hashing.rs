use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params, Version,
};
use sha2::{Digest, Sha256};
use tracing::instrument;

use crate::error::{AuthError, Result};

fn argon2() -> Result<Argon2<'static>> {
    let params = Params::new(65536, 3, 4, None)
        .map_err(|e| AuthError::HashError(e.to_string()))?;
    Ok(Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params))
}

#[instrument(skip(password))]
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2()?
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::HashError(e.to_string()))?
        .to_string();

    tracing::debug!("password hashed");
    Ok(hash)
}

#[instrument(skip(password, hash))]
pub fn verify_password(hash: &str, password: &str) -> Result<bool> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| AuthError::HashError(e.to_string()))?;

    let ok = argon2()?
        .verify_password(password.as_bytes(), &parsed)
        .is_ok();

    tracing::debug!(matched = ok, "password verified");
    Ok(ok)
}

/// SHA-256 hex digest — used for session token storage, never for passwords.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_correct_password() {
        let hash = hash_password("correct-horse-battery-staple").unwrap();
        assert!(verify_password(&hash, "correct-horse-battery-staple").unwrap());
    }

    #[test]
    fn wrong_password_returns_false() {
        let hash = hash_password("secret").unwrap();
        assert!(!verify_password(&hash, "wrong").unwrap());
    }

    #[test]
    fn sha256_hex_is_deterministic() {
        let a = sha256_hex(b"hello");
        let b = sha256_hex(b"hello");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn sha256_hex_different_inputs_differ() {
        assert_ne!(sha256_hex(b"a"), sha256_hex(b"b"));
    }
}
