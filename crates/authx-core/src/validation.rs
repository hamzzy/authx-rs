use email_address::EmailAddress;

use crate::error::{AuthError, Result};

/// Validate that `email` is a well-formed RFC 5322 address.
pub fn validate_email(email: &str) -> Result<()> {
    if EmailAddress::is_valid(email) {
        Ok(())
    } else {
        Err(AuthError::Internal(format!(
            "invalid email address: {email}"
        )))
    }
}

/// Validate password meets minimum security requirements:
/// - At least `min_len` characters
/// - At least one uppercase letter
/// - At least one digit
/// - At least one special character
pub fn validate_password(password: &str, min_len: usize) -> Result<()> {
    if password.len() < min_len {
        return Err(AuthError::WeakPassword);
    }
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(AuthError::WeakPassword);
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(AuthError::WeakPassword);
    }
    if !password
        .chars()
        .any(|c| !c.is_alphanumeric() && c.is_ascii())
    {
        return Err(AuthError::WeakPassword);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_email_passes() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("user+tag@sub.domain.io").is_ok());
    }

    #[test]
    fn invalid_email_rejected() {
        assert!(validate_email("notanemail").is_err());
        assert!(validate_email("@nodomain").is_err());
        assert!(validate_email("missing@").is_err());
        assert!(validate_email("").is_err());
    }

    #[test]
    fn strong_password_passes() {
        assert!(validate_password("Secure@123", 8).is_ok());
        assert!(validate_password("Tr0ub4dor&3", 8).is_ok());
    }

    #[test]
    fn weak_passwords_rejected() {
        assert!(validate_password("short", 8).is_err());
        assert!(validate_password("alllowercase1!", 8).is_err()); // no uppercase
        assert!(validate_password("NoDigitsHere!", 8).is_err()); // no digit
        assert!(validate_password("NoSpecial123", 8).is_err()); // no special char
    }
}
