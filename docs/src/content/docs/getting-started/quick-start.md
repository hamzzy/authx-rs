---
title: Quick Start
description: Get an authx-rs Axum server running in under 5 minutes.
---

import { Steps, Tabs, TabItem } from '@astrojs/starlight/components';

<Steps>

1. **Add the dependencies**

   ```toml title="Cargo.toml"
   [dependencies]
   authx-core    = { git = "https://github.com/authx/authx-rs" }
   authx-storage = { git = "https://github.com/authx/authx-rs" }
   authx-plugins = { git = "https://github.com/authx/authx-rs" }
   authx-axum    = { git = "https://github.com/authx/authx-rs" }

   axum              = "0.7"
   tokio             = { version = "1", features = ["full"] }
   tower-http        = { version = "0.6", features = ["trace"] }
   tracing-subscriber = { version = "0.3", features = ["env-filter"] }
   ```

2. **Write `main.rs`**

   ```rust title="src/main.rs"
   use std::time::Duration;

   use axum::{Router, routing::get, response::Json};
   use tower_http::trace::TraceLayer;
   use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

   use authx_axum::{
       csrf_middleware, AuthxState, CsrfConfig,
       RateLimitConfig, RateLimitLayer, RequireAuth, SessionLayer,
   };
   use authx_core::brute_force::LockoutConfig;
   use authx_storage::memory::MemoryStore;

   #[tokio::main]
   async fn main() {
       tracing_subscriber::registry()
           .with(EnvFilter::try_from_default_env()
               .unwrap_or_else(|_| "info,authx=debug".into()))
           .with(tracing_subscriber::fmt::layer())
           .init();

       let store = MemoryStore::new();

       // 5 failed sign-in attempts → 15-minute lockout
       let lockout = LockoutConfig::new(5, Duration::from_secs(900));

       let state = AuthxState::new_with_lockout(
           store.clone(),
           60 * 60 * 24 * 30, // 30-day sessions
           false,              // set true in production (Secure cookies)
           lockout,
       );

       let csrf = CsrfConfig::new(["http://localhost:3000"]);
       let rl   = RateLimitLayer::new(RateLimitConfig::new(20, Duration::from_secs(60)));

       let auth_router = state
           .router()
           .layer(rl)
           .route_layer(axum::middleware::from_fn_with_state(csrf, csrf_middleware));

       let app = Router::new()
           .route("/health", get(|| async { Json(serde_json::json!({ "ok": true })) }))
           .route("/me",     get(me))
           .nest("/auth",    auth_router)
           .layer(SessionLayer::new(store))
           .layer(TraceLayer::new_for_http());

       let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
       tracing::info!("listening on http://0.0.0.0:3000");
       axum::serve(listener, app).await.unwrap();
   }

   async fn me(RequireAuth(identity): RequireAuth) -> Json<serde_json::Value> {
       Json(serde_json::json!({
           "user_id": identity.user.id,
           "email":   identity.user.email,
       }))
   }
   ```

3. **Run the server**

   ```bash
   cargo run
   ```

4. **Try it out**

   ```bash
   # Register
   curl -s -X POST http://localhost:3000/auth/sign-up \
        -H 'Content-Type: application/json' \
        -H 'Origin: http://localhost:3000' \
        -d '{"email":"alice@example.com","password":"hunter2hunter2"}'

   # Sign in — saves session cookie to /tmp/jar
   curl -s -c /tmp/jar -X POST http://localhost:3000/auth/sign-in \
        -H 'Content-Type: application/json' \
        -H 'Origin: http://localhost:3000' \
        -d '{"email":"alice@example.com","password":"hunter2hunter2"}'

   # Access protected route
   curl -s -b /tmp/jar http://localhost:3000/me
   ```

</Steps>

## What's next

- Switch to PostgreSQL → see [PostgreSQL adapter](/storage/postgres/)
- Add TOTP MFA → see [TOTP Setup](/mfa/totp/)
- Add OAuth social login → see [OAuth (Social)](/auth/oauth/)
- Add the admin dashboard → see [Admin Dashboard](/http/dashboard/)
- Use the CLI → see [authx CLI](/cli/overview/)
