pub mod providers;
mod service;
#[cfg(test)]
mod tests;

pub use providers::github::GitHubProvider;
pub use providers::google::GoogleProvider;
pub use providers::{OAuthProvider, OAuthTokens, OAuthUserInfo};
pub use service::{OAuthBeginResponse, OAuthService};
