use async_trait::async_trait;
use axum::Router;

use authx_core::{error::Result, models::User};

/// Every auth feature is a Plugin.
///
/// Plugins register routes, react to lifecycle events, and can extend the
/// JWT payload and resolved Identity. The `setup` method is called once
/// during `Auth` initialization — use it to validate config and wire event
/// subscriptions.
#[async_trait]
pub trait Plugin: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    fn dependencies(&self) -> Vec<&'static str> {
        vec![]
    }

    async fn setup(&mut self) -> Result<()> {
        Ok(())
    }

    fn routes(&self) -> Option<Router> {
        None
    }

    async fn on_user_created(&self, _user: &User) -> Result<()> {
        Ok(())
    }

    fn extend_token_payload(&self, payload: &mut serde_json::Value, _user: &User) {
        let _ = payload;
    }
}
