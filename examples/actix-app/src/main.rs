/// actix-app — direct actix-web integration example for authx-rs
///
/// Demonstrates:
///  - framework-agnostic integration without `authx-axum`
///  - manual session cookie management in actix-web
///  - direct use of `EmailPasswordService`
///  - session lookup for protected handlers
///  - sign-up, sign-in, sign-out, session inspection, and protected routes
///
/// Run:
///   cargo run -p actix-app
///
/// Test with curl:
///   curl -s -X POST http://localhost:4000/auth/sign-up \
///        -H 'Content-Type: application/json' \
///        -d '{"email":"alice@example.com","password":"hunter2hunter2"}'
///
///   curl -s -c /tmp/actix-jar -X POST http://localhost:4000/auth/sign-in \
///        -H 'Content-Type: application/json' \
///        -d '{"email":"alice@example.com","password":"hunter2hunter2"}'
///
///   curl -s -b /tmp/actix-jar http://localhost:4000/auth/session
///   curl -s -b /tmp/actix-jar http://localhost:4000/me
use std::sync::Arc;
use std::time::Duration;

use actix_web::{
    cookie::{time::Duration as CookieDuration, Cookie, SameSite},
    http::{header, StatusCode},
    web, App, HttpRequest, HttpResponse, HttpServer,
};
use authx_core::{
    brute_force::LockoutConfig,
    crypto::sha256_hex,
    error::{AuthError, StorageError},
    events::EventBus,
    models::{Session, User},
};
use authx_plugins::email_password::{EmailPasswordService, SignInRequest, SignUpRequest};
use authx_storage::{
    ports::{SessionRepository, UserRepository},
    MemoryStore,
};
use serde::{Deserialize, Serialize};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

const SESSION_COOKIE: &str = "authx_session";
const SESSION_TTL_SECS: i64 = 60 * 60 * 24 * 30;

#[derive(Clone)]
struct AppState {
    store: MemoryStore,
    auth: Arc<EmailPasswordService<MemoryStore>>,
    session_ttl_secs: i64,
    secure_cookies: bool,
}

#[derive(Debug, Deserialize)]
struct CredentialsBody {
    email: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct AuthPayload {
    user: User,
    session: Session,
    token: String,
}

#[derive(Debug, Serialize)]
struct SessionPayload {
    user: User,
    session: Session,
}

#[derive(Debug, Serialize)]
struct ErrorPayload<'a> {
    error: &'a str,
    message: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,authx=debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let store = MemoryStore::new();
    let events = EventBus::new();
    let lockout = LockoutConfig::new(5, Duration::from_secs(60 * 15));

    let auth = Arc::new(
        EmailPasswordService::new(store.clone(), events, 12, SESSION_TTL_SECS)
            .with_lockout(lockout),
    );

    let state = web::Data::new(AppState {
        store,
        auth,
        session_ttl_secs: SESSION_TTL_SECS,
        secure_cookies: false,
    });

    let addr = "0.0.0.0:4000";
    tracing::info!("listening on http://{addr}");
    tracing::info!("sign up:  POST http://{addr}/auth/sign-up");
    tracing::info!("sign in:  POST http://{addr}/auth/sign-in");
    tracing::info!("session:  GET  http://{addr}/auth/session");

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/", web::get().to(index))
            .route("/health", web::get().to(health))
            .route("/me", web::get().to(me))
            .service(
                web::scope("/auth")
                    .route("/sign-up", web::post().to(sign_up))
                    .route("/sign-in", web::post().to(sign_in))
                    .route("/sign-out", web::post().to(sign_out))
                    .route("/sign-out/all", web::post().to(sign_out_all))
                    .route("/session", web::get().to(session))
                    .route("/sessions", web::get().to(sessions)),
            )
    })
    .bind(addr)?
    .run()
    .await
}

async fn index() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(
            r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>authx-rs actix-app</title>
  <style>
    body { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; margin: 2rem auto; max-width: 56rem; line-height: 1.5; padding: 0 1rem; }
    pre, code { background: #f6f8fa; border-radius: 6px; }
    code { padding: 0.1rem 0.35rem; }
    pre { padding: 1rem; overflow-x: auto; }
  </style>
</head>
<body>
  <h1>authx-rs actix-web example</h1>
  <p>This example shows direct framework integration without <code>authx-axum</code>.</p>
  <pre>curl -s -X POST http://localhost:4000/auth/sign-up \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"hunter2hunter2"}'

curl -s -c /tmp/actix-jar -X POST http://localhost:4000/auth/sign-in \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"hunter2hunter2"}'

curl -s -b /tmp/actix-jar http://localhost:4000/auth/session
curl -s -b /tmp/actix-jar http://localhost:4000/me</pre>
</body>
</html>"#,
        )
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({ "status": "ok" }))
}

async fn sign_up(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<CredentialsBody>,
) -> HttpResponse {
    match state
        .auth
        .sign_up(SignUpRequest {
            email: body.email.clone(),
            password: body.password.clone(),
            ip: request_ip(&req),
        })
        .await
    {
        Ok(user) => HttpResponse::Created().json(user),
        Err(err) => auth_error_response(err),
    }
}

async fn sign_in(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<CredentialsBody>,
) -> HttpResponse {
    match state
        .auth
        .sign_in(SignInRequest {
            email: body.email.clone(),
            password: body.password.clone(),
            ip: request_ip(&req),
        })
        .await
    {
        Ok(auth) => HttpResponse::Ok()
            .cookie(session_cookie(
                &auth.token,
                state.session_ttl_secs,
                state.secure_cookies,
            ))
            .json(AuthPayload {
                user: auth.user,
                session: auth.session,
                token: auth.token,
            }),
        Err(err) => auth_error_response(err),
    }
}

async fn sign_out(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let (_, session) = match resolve_session(&state, &req).await {
        Ok(found) => found,
        Err(err) => return auth_error_response(err),
    };

    match state.auth.sign_out(session.id).await {
        Ok(()) => HttpResponse::NoContent()
            .cookie(clear_session_cookie(state.secure_cookies))
            .finish(),
        Err(err) => auth_error_response(err),
    }
}

async fn sign_out_all(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let (user, _) = match resolve_session(&state, &req).await {
        Ok(found) => found,
        Err(err) => return auth_error_response(err),
    };

    match state.auth.sign_out_all(user.id).await {
        Ok(()) => HttpResponse::NoContent()
            .cookie(clear_session_cookie(state.secure_cookies))
            .finish(),
        Err(err) => auth_error_response(err),
    }
}

async fn session(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    match resolve_session(&state, &req).await {
        Ok((user, session)) => HttpResponse::Ok().json(SessionPayload { user, session }),
        Err(err) => auth_error_response(err),
    }
}

async fn sessions(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let (user, _) = match resolve_session(&state, &req).await {
        Ok(found) => found,
        Err(err) => return auth_error_response(err),
    };

    match state.auth.list_sessions(user.id).await {
        Ok(sessions) => HttpResponse::Ok().json(sessions),
        Err(err) => auth_error_response(err),
    }
}

async fn me(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    match resolve_session(&state, &req).await {
        Ok((user, session)) => HttpResponse::Ok().json(serde_json::json!({
            "user_id": user.id,
            "email": user.email,
            "verified": user.email_verified,
            "session_id": session.id,
            "active_org": session.org_id,
        })),
        Err(err) => auth_error_response(err),
    }
}

async fn resolve_session(
    state: &AppState,
    req: &HttpRequest,
) -> Result<(User, Session), AuthError> {
    let token = extract_token(req).ok_or(AuthError::SessionNotFound)?;
    let token_hash = sha256_hex(token.as_bytes());

    let session = SessionRepository::find_by_token_hash(&state.store, &token_hash)
        .await?
        .ok_or(AuthError::SessionNotFound)?;
    let user = UserRepository::find_by_id(&state.store, session.user_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    Ok((user, session))
}

fn extract_token(req: &HttpRequest) -> Option<String> {
    if let Some(cookie) = req.cookie(SESSION_COOKIE) {
        return Some(cookie.value().to_owned());
    }

    req.headers()
        .get("x-authx-token")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn request_ip(req: &HttpRequest) -> String {
    req.connection_info()
        .realip_remote_addr()
        .unwrap_or("127.0.0.1")
        .to_string()
}

fn session_cookie(token: &str, ttl_secs: i64, secure: bool) -> Cookie<'static> {
    Cookie::build(SESSION_COOKIE, token.to_owned())
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .max_age(CookieDuration::seconds(ttl_secs))
        .finish()
}

fn clear_session_cookie(secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::build(SESSION_COOKIE, "")
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .finish();
    cookie.make_removal();
    cookie
}

fn auth_error_response(err: AuthError) -> HttpResponse {
    let status = match &err {
        AuthError::InvalidCredentials => StatusCode::UNAUTHORIZED,
        AuthError::UserNotFound => StatusCode::NOT_FOUND,
        AuthError::SessionNotFound => StatusCode::UNAUTHORIZED,
        AuthError::EmailTaken => StatusCode::CONFLICT,
        AuthError::EmailNotVerified => StatusCode::FORBIDDEN,
        AuthError::InvalidToken => StatusCode::UNAUTHORIZED,
        AuthError::AccountLocked => StatusCode::TOO_MANY_REQUESTS,
        AuthError::WeakPassword => StatusCode::UNPROCESSABLE_ENTITY,
        AuthError::Forbidden(_) => StatusCode::FORBIDDEN,
        AuthError::Storage(StorageError::Conflict(_)) => StatusCode::CONFLICT,
        AuthError::Storage(StorageError::NotFound) => StatusCode::NOT_FOUND,
        AuthError::Storage(StorageError::Database(_))
        | AuthError::HashError(_)
        | AuthError::EncryptionError(_)
        | AuthError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };

    let code = match &err {
        AuthError::InvalidCredentials => "invalid_credentials",
        AuthError::UserNotFound => "user_not_found",
        AuthError::SessionNotFound => "session_not_found",
        AuthError::EmailTaken => "email_taken",
        AuthError::EmailNotVerified => "email_not_verified",
        AuthError::InvalidToken => "invalid_token",
        AuthError::AccountLocked => "account_locked",
        AuthError::WeakPassword => "weak_password",
        AuthError::Forbidden(_) => "forbidden",
        AuthError::Storage(StorageError::Conflict(_)) => "conflict",
        AuthError::Storage(StorageError::NotFound) => "not_found",
        AuthError::Storage(StorageError::Database(_))
        | AuthError::HashError(_)
        | AuthError::EncryptionError(_)
        | AuthError::Internal(_) => "internal_error",
    };

    HttpResponse::build(status)
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .json(ErrorPayload {
            error: code,
            message: err.to_string(),
        })
}
