pub mod admin;
pub mod base;
pub mod email_password;
pub mod magic_link;
pub mod one_time_token;
pub mod password_reset;
pub mod totp;

pub use admin::{AdminService, BanStatus};
pub use base::Plugin;
pub use email_password::EmailPasswordService;
pub use magic_link::{MagicLinkService, MagicLinkVerifyResponse};
pub use one_time_token::OneTimeTokenStore;
pub use password_reset::PasswordResetService;
pub use totp::{TotpService, TotpSetup};
