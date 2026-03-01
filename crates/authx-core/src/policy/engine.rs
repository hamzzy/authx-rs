use async_trait::async_trait;
use tracing::instrument;

use crate::error::{AuthError, Result};
use crate::identity::Identity;

#[derive(Debug, Clone)]
pub struct AuthzContext<'a> {
    pub action:      &'a str,
    pub identity:    &'a Identity,
    pub resource_id: Option<&'a str>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny,
    Abstain,
}

#[async_trait]
pub trait Policy: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    async fn evaluate(&self, ctx: &AuthzContext<'_>) -> PolicyDecision;
}

pub struct AuthzEngine {
    policies: Vec<Box<dyn Policy>>,
}

impl AuthzEngine {
    pub fn new() -> Self {
        Self { policies: Vec::new() }
    }

    pub fn add_policy(&mut self, policy: impl Policy) {
        self.policies.push(Box::new(policy));
    }

    /// Enforces authorization. Raises [`AuthError::Forbidden`] if denied.
    ///
    /// Evaluation order:
    /// 1. Walk policies in registration order.
    /// 2. First explicit Allow → permit.
    /// 3. First explicit Deny  → reject.
    /// 4. All Abstain          → fall through to RBAC check.
    #[instrument(skip(self, identity), fields(action, user_id = %identity.user.id))]
    pub async fn enforce(
        &self,
        action: &str,
        identity: &Identity,
        resource_id: Option<&str>,
    ) -> Result<()> {
        let ctx = AuthzContext { action, identity, resource_id };

        for policy in &self.policies {
            match policy.evaluate(&ctx).await {
                PolicyDecision::Allow   => {
                    tracing::debug!(action, policy = policy.name(), "policy allow");
                    return Ok(());
                }
                PolicyDecision::Deny => {
                    tracing::warn!(action, policy = policy.name(), "policy deny");
                    return Err(AuthError::Forbidden(format!(
                        "action '{action}' denied by policy '{}'",
                        policy.name()
                    )));
                }
                PolicyDecision::Abstain => {}
            }
        }

        // Default: RBAC from org membership
        if identity.has_permission(action) {
            tracing::debug!(action, "rbac allow");
            Ok(())
        } else {
            tracing::warn!(action, "rbac deny");
            Err(AuthError::Forbidden(format!(
                "action '{action}' not permitted for current role"
            )))
        }
    }
}

impl Default for AuthzEngine {
    fn default() -> Self {
        Self::new()
    }
}
