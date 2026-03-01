//! Redis-backed one-time token store — use with the `redis-tokens` feature.
//!
//! Drop-in replacement for [`OneTimeTokenStore`] for multi-instance deployments.
//! Tokens are stored with Redis `SET … EX` and consumed atomically with a Lua
//! GET+DEL script.
#[cfg(feature = "redis-tokens")]
mod inner {
    use redis::{aio::MultiplexedConnection, AsyncCommands, Client, Script};
    use uuid::Uuid;

    use crate::one_time_token::TokenKind;
    use authx_core::crypto::sha256_hex;
    use authx_core::error::{AuthError, Result};

    /// Serialization envelope stored in Redis.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct RedisRecord {
        kind: u8,
        user_id: Uuid,
    }

    fn kind_byte(k: &TokenKind) -> u8 {
        match k {
            TokenKind::PasswordReset => 0,
            TokenKind::MagicLink => 1,
            TokenKind::EmailVerification => 2,
            TokenKind::EmailOtp => 3,
        }
    }

    fn kind_from_byte(b: u8) -> Option<TokenKind> {
        match b {
            0 => Some(TokenKind::PasswordReset),
            1 => Some(TokenKind::MagicLink),
            2 => Some(TokenKind::EmailVerification),
            3 => Some(TokenKind::EmailOtp),
            _ => None,
        }
    }

    /// Redis-backed single-use token store.
    ///
    /// # Usage
    /// ```rust,ignore
    /// let store = RedisTokenStore::connect("redis://127.0.0.1/").await?;
    /// let token = store.issue(user_id, TokenKind::MagicLink, 900).await?;
    /// let uid   = store.consume(&token, TokenKind::MagicLink).await?;
    /// ```
    #[derive(Clone)]
    pub struct RedisTokenStore {
        client: Client,
    }

    impl RedisTokenStore {
        pub async fn connect(redis_url: &str) -> Result<Self> {
            let client = Client::open(redis_url)
                .map_err(|e| AuthError::Internal(format!("redis connect: {e}")))?;
            tracing::info!("redis token store connected");
            Ok(Self { client })
        }

        async fn conn(&self) -> Result<MultiplexedConnection> {
            self.client
                .get_multiplexed_async_connection()
                .await
                .map_err(|e| AuthError::Internal(format!("redis connection: {e}")))
        }

        /// Issue a token with `ttl_seconds` expiry. Returns the raw (un-hashed) token.
        pub async fn issue(
            &self,
            user_id: Uuid,
            kind: TokenKind,
            ttl_seconds: u64,
        ) -> Result<String> {
            let raw: [u8; 32] = rand::Rng::gen(&mut rand::thread_rng());
            let token = hex::encode(raw);
            let hash = sha256_hex(token.as_bytes());

            let record = RedisRecord {
                kind: kind_byte(&kind),
                user_id,
            };
            let json = serde_json::to_string(&record)
                .map_err(|e| AuthError::Internal(format!("redis token serialize: {e}")))?;

            let mut conn = self.conn().await?;
            let _: () = conn
                .set_ex(&hash, json, ttl_seconds)
                .await
                .map_err(|e| AuthError::Internal(format!("redis SET: {e}")))?;

            tracing::debug!(user_id = %user_id, "redis: one-time token issued");
            Ok(token)
        }

        /// Consume a token atomically (Lua GET+DEL). Returns `None` if the token
        /// is expired, not found, or the wrong kind.
        pub async fn consume(
            &self,
            raw_token: &str,
            expected_kind: TokenKind,
        ) -> Result<Option<Uuid>> {
            let hash = sha256_hex(raw_token.as_bytes());

            // Atomic GET+DEL via Lua so no other replica can consume the same token.
            let lua = Script::new(
                r#"
                local val = redis.call('GET', KEYS[1])
                if val == false then return nil end
                redis.call('DEL', KEYS[1])
                return val
                "#,
            );

            let mut conn = self.conn().await?;
            let raw_json: Option<String> = lua
                .key(&hash)
                .invoke_async(&mut conn)
                .await
                .map_err(|e| AuthError::Internal(format!("redis lua: {e}")))?;

            let json = match raw_json {
                Some(j) => j,
                None => {
                    tracing::debug!("redis: token not found or expired");
                    return Ok(None);
                }
            };

            let record: RedisRecord = serde_json::from_str(&json)
                .map_err(|e| AuthError::Internal(format!("redis token deserialize: {e}")))?;

            if kind_from_byte(record.kind).as_ref() != Some(&expected_kind) {
                tracing::debug!("redis: token kind mismatch");
                return Ok(None);
            }

            tracing::debug!(user_id = %record.user_id, "redis: one-time token consumed");
            Ok(Some(record.user_id))
        }
    }
}

#[cfg(feature = "redis-tokens")]
pub use inner::RedisTokenStore;
