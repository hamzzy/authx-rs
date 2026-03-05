//! OIDC Discovery document and JWKS for authx as IdP.

use serde::{Deserialize, Serialize};

/// Generate the OIDC discovery document (JSON for /.well-known/openid-configuration).
pub fn oidc_discovery_document(issuer: &str, base_path: &str) -> DiscoveryDocument {
    let issuer = issuer.trim_end_matches('/');
    let base = if base_path.is_empty() {
        issuer.to_string()
    } else {
        format!("{issuer}{}", base_path.trim_end_matches('/'))
    };
    DiscoveryDocument {
        issuer: issuer.to_string(),
        authorization_endpoint: format!("{base}/authorize"),
        token_endpoint: format!("{base}/token"),
        device_authorization_endpoint: format!("{base}/device_authorization"),
        userinfo_endpoint: format!("{base}/userinfo"),
        jwks_uri: format!("{base}/jwks"),
        scopes_supported: vec!["openid".into(), "profile".into(), "email".into()],
        response_types_supported: vec!["code".into()],
        grant_types_supported: vec![
            "authorization_code".into(),
            "refresh_token".into(),
            "urn:ietf:params:oauth:grant-type:device_code".into(),
        ],
        token_endpoint_auth_methods_supported: vec![
            "client_secret_post".into(),
            "client_secret_basic".into(),
        ],
        subject_types_supported: vec!["public".into()],
        id_token_signing_alg_values_supported: vec!["EdDSA".into()],
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub device_authorization_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
}
