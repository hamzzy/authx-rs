pub mod routes;
pub mod service;

#[cfg(test)]
mod tests;

pub use authx_core::brute_force::LockoutConfig;
pub use service::{AuthResponse, EmailPasswordService, SignInRequest, SignUpRequest};
