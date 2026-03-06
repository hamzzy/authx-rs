pub mod admin;
pub mod anonymous;
pub mod api_key;
pub mod base;
pub mod email_otp;
pub mod email_password;
pub mod email_verification;
pub mod magic_link;
pub mod oauth;
pub mod oidc_federation;
pub mod oidc_provider;
pub mod one_time_token;
pub mod organization;
pub mod password_reset;
pub mod totp;
pub mod username;
pub mod webauthn;

pub use admin::{AdminService, BanStatus};
pub use anonymous::{AnonymousService, GuestSession};
pub use api_key::{ApiKeyResponse, ApiKeyService};
pub use base::Plugin;
pub use email_otp::{EmailOtpService, EmailOtpVerifyResponse};
pub use email_password::EmailPasswordService;
pub use email_verification::EmailVerificationService;
pub use magic_link::{MagicLinkService, MagicLinkVerifyResponse};
pub use oauth::{GitHubProvider, GoogleProvider, OAuthService};
pub use oidc_federation::{OidcFederationBeginResponse, OidcFederationService};
pub use oidc_provider::{
    DeviceAuthorizationResponse, DeviceCodeError, OidcProviderConfig, OidcProviderService,
    OidcTokenResponse,
};
pub use one_time_token::OneTimeTokenStore;
pub use organization::{InviteDetails, OrgService};
pub use password_reset::PasswordResetService;
pub use totp::{TotpService, TotpSetup};
pub use username::{UsernameAuthResponse, UsernameService};
pub use webauthn::{
    FinishAuthenticationRequest, FinishRegistrationRequest, WebAuthnAuthenticationResult,
    WebAuthnBeginResponse, WebAuthnRegistrationResult, WebAuthnService,
};

#[cfg(feature = "redis-tokens")]
pub mod redis_token_store;
