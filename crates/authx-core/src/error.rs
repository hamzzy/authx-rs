use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("user not found")]
    UserNotFound,

    #[error("session not found or expired")]
    SessionNotFound,

    #[error("email already in use")]
    EmailTaken,

    #[error("email not verified")]
    EmailNotVerified,

    #[error("token is invalid or expired")]
    InvalidToken,

    #[error("password hash failed: {0}")]
    HashError(String),

    #[error("encryption error: {0}")]
    EncryptionError(String),

    #[error("access denied: {0}")]
    Forbidden(String),

    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("record not found")]
    NotFound,

    #[error("constraint violation: {0}")]
    Conflict(String),

    #[error("database error: {0}")]
    Database(String),
}

pub type Result<T> = std::result::Result<T, AuthError>;
