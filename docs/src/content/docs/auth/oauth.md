---
title: OAuth (Social Login)
description: Sign in with Google or GitHub using OAuth2 + PKCE.
---

import { Aside } from '@astrojs/starlight/components';

The `OAuthService` lets users authenticate via external OAuth2 providers (Google, GitHub). It implements the **Authorization Code flow with PKCE** and stores OAuth tokens encrypted with AES-256-GCM.

## Supported providers

| Provider | Scopes | Notes |
|---|---|---|
| Google | `openid email profile` | Uses OIDC userinfo endpoint |
| GitHub | `read:user user:email` | Fetches primary verified email |

Custom providers are supported by implementing the `OAuthProvider` trait.

## Setup

```rust
use authx_plugins::{OAuthService, GoogleProvider, GitHubProvider};
use authx_core::crypto::generate_key; // AES-256-GCM key for token encryption

let encryption_key = std::env::var("OAUTH_ENCRYPTION_KEY").expect("32-byte hex key");

let svc = OAuthService::new(store.clone(), events.clone(), encryption_key)
    .add_provider(GoogleProvider::new(
        std::env::var("GOOGLE_CLIENT_ID").unwrap(),
        std::env::var("GOOGLE_CLIENT_SECRET").unwrap(),
        "https://app.example.com/auth/oauth/google/callback",
    ))
    .add_provider(GitHubProvider::new(
        std::env::var("GITHUB_CLIENT_ID").unwrap(),
        std::env::var("GITHUB_CLIENT_SECRET").unwrap(),
        "https://app.example.com/auth/oauth/github/callback",
    ));
```

## Step 1 — Begin authorization

```rust
let resp = svc.begin("google", "https://app.example.com/auth/oauth/google/callback").await?;

// Store resp.state and resp.code_verifier in the user's session/cookie
// Redirect the user to resp.authorization_url
```

## Step 2 — Handle callback

```rust
// In your callback handler:
let resp = svc.callback(
    "google",
    &code,           // from query string
    &state,          // from query string — verify it matches stored state
    &code_verifier,  // from session/cookie
    "client-ip",
).await?;

resp.token    // session token
resp.user     // created or found user
resp.session
```

## Custom provider

```rust
use authx_plugins::oauth::providers::{OAuthProvider, OAuthTokens, OAuthUserInfo};
use authx_core::error::Result;
use async_trait::async_trait;

struct MyProvider { client_id: String, client_secret: String, redirect_uri: String }

#[async_trait]
impl OAuthProvider for MyProvider {
    fn name(&self) -> &'static str { "myprovider" }

    fn authorization_url(&self, state: &str, pkce_challenge: &str) -> String {
        format!(
            "https://auth.myprovider.com/oauth/authorize\
             ?client_id={}&redirect_uri={}&state={}&code_challenge={}&code_challenge_method=S256\
             &response_type=code",
            self.client_id, urlencoding::encode(&self.redirect_uri), state, pkce_challenge
        )
    }

    async fn exchange_code(&self, code: &str, pkce_verifier: &str) -> Result<OAuthTokens> {
        // POST to token endpoint
        todo!()
    }

    async fn fetch_user_info(&self, access_token: &str) -> Result<OAuthUserInfo> {
        // GET /userinfo or equivalent
        todo!()
    }
}
```

## Security

- PKCE (`S256`) is always used — state parameter alone is not sufficient
- Access and refresh tokens are stored **AES-256-GCM encrypted** in the database
- OAuth accounts are linked to authx users by email; if an account with the same email already exists, the OAuth identity is linked to it

<Aside type="caution">
Store `OAUTH_ENCRYPTION_KEY` in a secret manager (AWS Secrets Manager, HashiCorp Vault, etc.) and rotate it periodically.
</Aside>
