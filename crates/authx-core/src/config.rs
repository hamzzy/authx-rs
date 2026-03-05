//! Unified typed configuration for authx-rs.
//!
//! `AuthxConfig` consolidates all configuration knobs used by the CLI, dashboard,
//! plugins, and runtime. It supports construction via builder pattern, direct
//! instantiation with defaults, or loading from environment variables.

use std::time::Duration;

/// Central configuration for authx-rs services.
///
/// All fields carry sensible defaults. Use [`AuthxConfig::from_env`] to override
/// any field via environment variables (prefix `AUTHX_`), or construct directly.
#[derive(Debug, Clone)]
pub struct AuthxConfig {
    // ── Server ──────────────────────────────────────────────────
    /// Bind address (e.g. `0.0.0.0:3000`).
    pub bind: String,
    /// Database URL. `None` ⇒ in-memory store.
    pub database_url: Option<String>,
    /// Enable HTTPS-only cookies.
    pub secure_cookies: bool,

    // ── Session ─────────────────────────────────────────────────
    /// Session TTL in seconds (default: 30 days).
    pub session_ttl_secs: i64,

    // ── CSRF ────────────────────────────────────────────────────
    /// Trusted origins for CSRF validation (comma-separated in env).
    pub trusted_origins: Vec<String>,

    // ── Rate limiting ───────────────────────────────────────────
    /// Max requests per rate-limit window on auth routes.
    pub rate_limit_max: u32,
    /// Rate-limit window duration.
    pub rate_limit_window: Duration,

    // ── Account lockout ─────────────────────────────────────────
    /// Number of failures before lockout.
    pub lockout_max_failures: u32,
    /// Lockout window duration.
    pub lockout_window: Duration,

    // ── Encryption ──────────────────────────────────────────────
    /// 32-byte hex-encoded encryption key for OAuth/federation tokens.
    /// `None` ⇒ random key generated at startup (tokens won't survive restart).
    pub encryption_key_hex: Option<String>,

    // ── OIDC Provider ───────────────────────────────────────────
    /// Issuer URL for the built-in OIDC provider.
    pub oidc_issuer: Option<String>,
    /// Access token TTL in seconds.
    pub oidc_access_token_ttl_secs: i64,
    /// ID token TTL in seconds.
    pub oidc_id_token_ttl_secs: i64,
    /// Refresh token TTL in seconds.
    pub oidc_refresh_token_ttl_secs: i64,
    /// Authorization code TTL in seconds.
    pub oidc_auth_code_ttl_secs: i64,
    /// Device code TTL in seconds.
    pub oidc_device_code_ttl_secs: i64,
    /// Device code poll interval in seconds.
    pub oidc_device_code_interval_secs: u32,
    /// Verification URI for device flow.
    pub oidc_verification_uri: Option<String>,
}

impl Default for AuthxConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:3000".into(),
            database_url: None,
            secure_cookies: false,

            session_ttl_secs: 60 * 60 * 24 * 30, // 30 days

            trusted_origins: vec!["http://localhost:3000".into()],

            rate_limit_max: 30,
            rate_limit_window: Duration::from_secs(60),

            lockout_max_failures: 5,
            lockout_window: Duration::from_secs(15 * 60),

            encryption_key_hex: None,

            oidc_issuer: None,
            oidc_access_token_ttl_secs: 3600,
            oidc_id_token_ttl_secs: 3600,
            oidc_refresh_token_ttl_secs: 60 * 60 * 24 * 30,
            oidc_auth_code_ttl_secs: 600,
            oidc_device_code_ttl_secs: 600,
            oidc_device_code_interval_secs: 5,
            oidc_verification_uri: None,
        }
    }
}

impl AuthxConfig {
    /// Load configuration from environment variables with `AUTHX_` prefix.
    ///
    /// Every field falls back to [`Default`] when its env var is absent.
    ///
    /// | Field                 | Env var                            |
    /// |-----------------------|------------------------------------|
    /// | `bind`                | `AUTHX_BIND`                       |
    /// | `database_url`        | `DATABASE_URL`                     |
    /// | `secure_cookies`      | `AUTHX_SECURE_COOKIES`             |
    /// | `session_ttl_secs`    | `AUTHX_SESSION_TTL`                |
    /// | `trusted_origins`     | `AUTHX_TRUSTED_ORIGINS` (comma)    |
    /// | `rate_limit_max`      | `AUTHX_RATE_LIMIT`                 |
    /// | `rate_limit_window`   | `AUTHX_RATE_LIMIT_WINDOW_SECS`     |
    /// | `lockout_max_failures`| `AUTHX_LOCKOUT_FAILURES`           |
    /// | `lockout_window`      | `AUTHX_LOCKOUT_MINUTES`            |
    /// | `encryption_key_hex`  | `AUTHX_ENCRYPTION_KEY`             |
    /// | `oidc_issuer`         | `AUTHX_OIDC_ISSUER`                |
    /// | `oidc_*_ttl_secs`     | `AUTHX_OIDC_ACCESS_TOKEN_TTL` etc. |
    pub fn from_env() -> Self {
        let defaults = Self::default();

        Self {
            bind: env_or("AUTHX_BIND", defaults.bind),
            database_url: std::env::var("DATABASE_URL").ok().or(defaults.database_url),
            secure_cookies: env_parse("AUTHX_SECURE_COOKIES", defaults.secure_cookies),
            session_ttl_secs: env_parse("AUTHX_SESSION_TTL", defaults.session_ttl_secs),
            trusted_origins: std::env::var("AUTHX_TRUSTED_ORIGINS")
                .map(|s| s.split(',').map(|o| o.trim().to_owned()).collect())
                .unwrap_or(defaults.trusted_origins),
            rate_limit_max: env_parse("AUTHX_RATE_LIMIT", defaults.rate_limit_max),
            rate_limit_window: Duration::from_secs(env_parse(
                "AUTHX_RATE_LIMIT_WINDOW_SECS",
                defaults.rate_limit_window.as_secs(),
            )),
            lockout_max_failures: env_parse(
                "AUTHX_LOCKOUT_FAILURES",
                defaults.lockout_max_failures,
            ),
            lockout_window: Duration::from_secs(
                env_parse(
                    "AUTHX_LOCKOUT_MINUTES",
                    defaults.lockout_window.as_secs() / 60,
                ) * 60,
            ),
            encryption_key_hex: std::env::var("AUTHX_ENCRYPTION_KEY")
                .ok()
                .or(defaults.encryption_key_hex),
            oidc_issuer: std::env::var("AUTHX_OIDC_ISSUER")
                .ok()
                .or(defaults.oidc_issuer),
            oidc_access_token_ttl_secs: env_parse(
                "AUTHX_OIDC_ACCESS_TOKEN_TTL",
                defaults.oidc_access_token_ttl_secs,
            ),
            oidc_id_token_ttl_secs: env_parse(
                "AUTHX_OIDC_ID_TOKEN_TTL",
                defaults.oidc_id_token_ttl_secs,
            ),
            oidc_refresh_token_ttl_secs: env_parse(
                "AUTHX_OIDC_REFRESH_TOKEN_TTL",
                defaults.oidc_refresh_token_ttl_secs,
            ),
            oidc_auth_code_ttl_secs: env_parse(
                "AUTHX_OIDC_AUTH_CODE_TTL",
                defaults.oidc_auth_code_ttl_secs,
            ),
            oidc_device_code_ttl_secs: env_parse(
                "AUTHX_OIDC_DEVICE_CODE_TTL",
                defaults.oidc_device_code_ttl_secs,
            ),
            oidc_device_code_interval_secs: env_parse(
                "AUTHX_OIDC_DEVICE_INTERVAL",
                defaults.oidc_device_code_interval_secs,
            ),
            oidc_verification_uri: std::env::var("AUTHX_OIDC_VERIFICATION_URI")
                .ok()
                .or(defaults.oidc_verification_uri),
        }
    }

    /// Parse the 32-byte encryption key from hex, or generate a random one.
    pub fn encryption_key(&self) -> [u8; 32] {
        if let Some(hex_str) = &self.encryption_key_hex {
            let bytes = hex::decode(hex_str).expect("AUTHX_ENCRYPTION_KEY must be valid hex");
            let mut key = [0u8; 32];
            assert!(
                bytes.len() == 32,
                "AUTHX_ENCRYPTION_KEY must be exactly 32 bytes (64 hex chars)"
            );
            key.copy_from_slice(&bytes);
            key
        } else {
            rand::random()
        }
    }
}

fn env_or(key: &str, default: String) -> String {
    std::env::var(key).unwrap_or(default)
}

fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let cfg = AuthxConfig::default();
        assert_eq!(cfg.bind, "0.0.0.0:3000");
        assert_eq!(cfg.session_ttl_secs, 60 * 60 * 24 * 30);
        assert!(!cfg.secure_cookies);
        assert_eq!(cfg.lockout_max_failures, 5);
        assert_eq!(cfg.rate_limit_max, 30);
        assert_eq!(cfg.oidc_access_token_ttl_secs, 3600);
    }

    #[test]
    fn encryption_key_random_when_unset() {
        let cfg = AuthxConfig::default();
        let k1 = cfg.encryption_key();
        let k2 = cfg.encryption_key();
        // Two random keys should differ (probabilistically)
        assert_ne!(k1, k2);
    }
}
