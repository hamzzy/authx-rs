use axum::{response::Html, routing::get, Router};

static INDEX_HTML: &str = include_str!("../assets/index.html");

pub(crate) fn routes() -> Router {
    Router::new().route("/", get(index))
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}
