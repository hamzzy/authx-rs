pub mod cookies;
pub mod csrf;
pub mod errors;
pub mod extractors;
pub mod handlers;
pub mod middleware;
pub mod oidc;
pub mod rate_limit;
pub mod webauthn;

pub use cookies::{clear_session_cookie, set_session_cookie};
pub use csrf::{csrf_middleware, CsrfConfig};
pub use errors::AuthErrorResponse;
pub use extractors::{AuthRejection, RequireAuth, RequireRole};
pub use handlers::AuthxState;
pub use middleware::SessionLayer;
pub use oidc::{
    oidc_federation_router, oidc_provider_router, OidcFederationState, OidcProviderState,
};
pub use rate_limit::{RateLimitConfig, RateLimitLayer};
pub use webauthn::webauthn_router;
