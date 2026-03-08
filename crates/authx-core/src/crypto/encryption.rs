use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
};
use tracing::instrument;

use crate::error::{AuthError, Result};

const NONCE_LEN: usize = 12;

/// Encrypts plaintext with AES-256-GCM. Returns `nonce || ciphertext` as hex.
#[instrument(skip(key, plaintext))]
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<String> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| AuthError::EncryptionError(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| AuthError::EncryptionError(e.to_string()))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);

    tracing::debug!("encrypted {} bytes", plaintext.len());
    Ok(hex::encode(out))
}

/// Decrypts hex-encoded `nonce || ciphertext` produced by [`encrypt`].
#[instrument(skip(key, hex_blob))]
pub fn decrypt(key: &[u8; 32], hex_blob: &str) -> Result<Vec<u8>> {
    let raw =
        hex::decode(hex_blob).map_err(|_| AuthError::EncryptionError("invalid hex".into()))?;

    if raw.len() < NONCE_LEN {
        return Err(AuthError::EncryptionError("blob too short".into()));
    }

    let (nonce_bytes, ciphertext) = raw.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| AuthError::EncryptionError(e.to_string()))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| AuthError::EncryptionError("decryption failed".into()))?;

    tracing::debug!("decrypted {} bytes", plaintext.len());
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn round_trip_plaintext() {
        let key = test_key();
        let plaintext = b"oauth-access-token-secret";
        let blob = encrypt(&key, plaintext).unwrap();
        let recovered = decrypt(&key, &blob).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn different_nonce_each_call() {
        let key = test_key();
        let a = encrypt(&key, b"same").unwrap();
        let b = encrypt(&key, b"same").unwrap();
        assert_ne!(a, b, "nonce must be randomised per call");
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = [0x11u8; 32];
        let key2 = [0x22u8; 32];
        let blob = encrypt(&key1, b"secret").unwrap();
        assert!(decrypt(&key2, &blob).is_err());
    }

    #[test]
    fn truncated_blob_fails() {
        let key = test_key();
        assert!(decrypt(&key, "deadbeef").is_err());
    }
}
