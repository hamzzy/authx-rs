use axum::http::HeaderValue;
use cookie::{Cookie, SameSite};

const SESSION_COOKIE: &str = "authx_session";

/// Build a `Set-Cookie` header value for the session token.
///
/// Flags set by default:
/// - `HttpOnly`    — not accessible from JS
/// - `Secure`      — HTTPS only (set `secure = false` for local dev)
/// - `SameSite=Lax` — protects against CSRF while allowing top-level nav
/// - `Path=/`
pub fn set_session_cookie(token: &str, max_age_seconds: i64, secure: bool) -> HeaderValue {
    let mut cookie = Cookie::build((SESSION_COOKIE, token.to_owned()))
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(cookie::time::Duration::seconds(max_age_seconds));

    if secure {
        cookie = cookie.secure(true);
    }

    HeaderValue::from_str(&cookie.build().to_string())
        .expect("cookie value is always valid ASCII")
}

/// Build a `Set-Cookie` header that immediately expires the session cookie.
pub fn clear_session_cookie(secure: bool) -> HeaderValue {
    set_session_cookie("", 0, secure)
}
