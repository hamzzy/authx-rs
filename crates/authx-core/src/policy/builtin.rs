/// Built-in ABAC policy implementations ready for use with [`AuthzEngine`].
///
/// Compose these with `engine.add_policy(...)` or use them as reference
/// implementations for custom policies.
use std::collections::HashSet;
use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{Datelike, Timelike, Utc, Weekday};

use super::engine::{AuthzContext, Policy, PolicyDecision};

// ── OrgBoundaryPolicy ─────────────────────────────────────────────────────────

/// Denies any action when the identity carries an org context but the
/// current request targets a resource from a *different* org.
///
/// Resource IDs are expected in the form `"org:<uuid>:<rest>"`.
/// If the resource ID doesn't match that prefix the policy abstains.
///
/// # Example
/// ```rust,ignore
/// engine.add_policy(OrgBoundaryPolicy);
/// engine.enforce("read", &identity, Some("org:550e8400-e29b-41d4-a716-446655440000:report")).await?;
/// ```
pub struct OrgBoundaryPolicy;

#[async_trait]
impl Policy for OrgBoundaryPolicy {
    fn name(&self) -> &'static str { "org_boundary" }

    async fn evaluate(&self, ctx: &AuthzContext<'_>) -> PolicyDecision {
        let Some(resource_id) = ctx.resource_id else {
            return PolicyDecision::Abstain;
        };

        // Expected format: "org:<org_uuid>:<rest>"
        let Some(rest) = resource_id.strip_prefix("org:") else {
            return PolicyDecision::Abstain;
        };

        let resource_org = rest.split(':').next().unwrap_or("");
        if resource_org.is_empty() {
            return PolicyDecision::Abstain;
        }

        let active_org = match &ctx.identity.active_org {
            Some(o) => o.id.to_string(),
            None    => return PolicyDecision::Deny, // resource is org-scoped; no active org → deny
        };

        if active_org == resource_org {
            PolicyDecision::Abstain // let RBAC make the final call
        } else {
            tracing::warn!(
                user_id  = %ctx.identity.user.id,
                active   = %active_org,
                resource = %resource_org,
                "org boundary violation"
            );
            PolicyDecision::Deny
        }
    }
}

// ── TimeWindowPolicy ──────────────────────────────────────────────────────────

/// Restricts actions to specific hours (UTC) and optional weekdays.
///
/// # Example — allow only on weekdays between 09:00 and 18:00 UTC
/// ```rust,ignore
/// engine.add_policy(TimeWindowPolicy::weekdays(9, 18));
/// ```
pub struct TimeWindowPolicy {
    /// Inclusive start hour (0–23, UTC).
    start_hour: u32,
    /// Exclusive end hour (0–23, UTC).
    end_hour:   u32,
    /// If `Some`, only allow on these weekdays.
    weekdays:   Option<HashSet<Weekday>>,
}

impl TimeWindowPolicy {
    pub fn new(start_hour: u32, end_hour: u32) -> Self {
        Self { start_hour, end_hour, weekdays: None }
    }

    pub fn weekdays(start_hour: u32, end_hour: u32) -> Self {
        use Weekday::*;
        Self {
            start_hour,
            end_hour,
            weekdays: Some([Mon, Tue, Wed, Thu, Fri].into()),
        }
    }

    pub fn with_days(mut self, days: impl IntoIterator<Item = Weekday>) -> Self {
        self.weekdays = Some(days.into_iter().collect());
        self
    }
}

#[async_trait]
impl Policy for TimeWindowPolicy {
    fn name(&self) -> &'static str { "time_window" }

    async fn evaluate(&self, ctx: &AuthzContext<'_>) -> PolicyDecision {
        let now  = Utc::now();
        let hour = now.hour();

        if let Some(days) = &self.weekdays {
            if !days.contains(&now.weekday()) {
                tracing::warn!(
                    user_id = %ctx.identity.user.id,
                    action  = ctx.action,
                    weekday = ?now.weekday(),
                    "time_window: wrong weekday"
                );
                return PolicyDecision::Deny;
            }
        }

        if hour >= self.start_hour && hour < self.end_hour {
            PolicyDecision::Abstain
        } else {
            tracing::warn!(
                user_id     = %ctx.identity.user.id,
                action      = ctx.action,
                hour        = hour,
                start_hour  = self.start_hour,
                end_hour    = self.end_hour,
                "time_window: outside allowed hours"
            );
            PolicyDecision::Deny
        }
    }
}

// ── IpAllowListPolicy ─────────────────────────────────────────────────────────

/// Denies actions from IPs not in the allow-list.
///
/// The IP is read from `identity.session.ip_address`.
///
/// # Example
/// ```rust,ignore
/// engine.add_policy(IpAllowListPolicy::new(["10.0.0.0/8", "192.168.1.0/24"]));
/// ```
pub struct IpAllowListPolicy {
    /// Allowed IP prefixes (CIDR prefix string, e.g. `"10.0."`, `"192.168.1."`).
    /// For simplicity this matches on string prefix rather than a CIDR library
    /// to keep authx-core dependency-free.
    allowed_prefixes: Vec<String>,
}

impl IpAllowListPolicy {
    /// Accepts CIDR-style prefix strings (`"10.0."`, `"192.168.1.0"`, full IPs).
    pub fn new(prefixes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            allowed_prefixes: prefixes.into_iter().map(|s| s.into()).collect(),
        }
    }
}

#[async_trait]
impl Policy for IpAllowListPolicy {
    fn name(&self) -> &'static str { "ip_allow_list" }

    async fn evaluate(&self, ctx: &AuthzContext<'_>) -> PolicyDecision {
        let ip = &ctx.identity.session.ip_address;

        // Empty IP (e.g. tests without ConnectInfo) → abstain.
        if ip.is_empty() {
            return PolicyDecision::Abstain;
        }

        // Parse as IpAddr for exact matching, fall back to prefix match.
        let parsed: Option<IpAddr> = ip.parse().ok();

        let allowed = self.allowed_prefixes.iter().any(|prefix| {
            if let (Some(client), Ok(allowed_ip)) = (parsed, prefix.parse::<IpAddr>()) {
                client == allowed_ip
            } else {
                ip.starts_with(prefix.as_str())
            }
        });

        if allowed {
            PolicyDecision::Abstain // IP is fine; let RBAC decide
        } else {
            tracing::warn!(ip = %ip, action = ctx.action, "ip_allow_list: blocked");
            PolicyDecision::Deny
        }
    }
}

// ── RequireEmailVerifiedPolicy ────────────────────────────────────────────────

/// Denies sensitive actions (configurable action prefix) when the user's
/// email is not verified.
pub struct RequireEmailVerifiedPolicy {
    /// Only enforce on actions with this prefix (e.g. `"admin."`, `"billing."`).
    /// `None` = enforce on all actions.
    action_prefix: Option<String>,
}

impl RequireEmailVerifiedPolicy {
    pub fn all_actions() -> Self { Self { action_prefix: None } }

    pub fn for_prefix(prefix: impl Into<String>) -> Self {
        Self { action_prefix: Some(prefix.into()) }
    }
}

#[async_trait]
impl Policy for RequireEmailVerifiedPolicy {
    fn name(&self) -> &'static str { "require_email_verified" }

    async fn evaluate(&self, ctx: &AuthzContext<'_>) -> PolicyDecision {
        if let Some(prefix) = &self.action_prefix {
            if !ctx.action.starts_with(prefix.as_str()) {
                return PolicyDecision::Abstain;
            }
        }

        if ctx.identity.user.email_verified {
            PolicyDecision::Abstain
        } else {
            tracing::warn!(
                user_id = %ctx.identity.user.id,
                action  = ctx.action,
                "require_email_verified: email not verified"
            );
            PolicyDecision::Deny
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::Identity,
        models::{Session, User},
        policy::engine::{AuthzContext, Policy, PolicyDecision},
    };
    use chrono::Utc;
    use uuid::Uuid;

    fn dummy_user(verified: bool) -> User {
        User {
            id:             Uuid::new_v4(),
            email:          "test@example.com".into(),
            email_verified: verified,
            created_at:     Utc::now(),
            updated_at:     Utc::now(),
            metadata:       serde_json::Value::Null,
        }
    }

    fn dummy_session(ip: &str) -> Session {
        Session {
            id:          Uuid::new_v4(),
            user_id:     Uuid::new_v4(),
            token_hash:  "hash".into(),
            device_info: serde_json::Value::Null,
            ip_address:  ip.into(),
            org_id:      None,
            expires_at:  Utc::now() + chrono::Duration::hours(1),
            created_at:  Utc::now(),
        }
    }

    fn identity(user: User, session: Session) -> Identity {
        Identity::new(user, session)
    }

    // ── IpAllowListPolicy ────────────────────────────────────────────────────

    #[tokio::test]
    async fn ip_allow_list_permits_matching_ip() {
        let policy = IpAllowListPolicy::new(["10.0.0.1"]);
        let id  = identity(dummy_user(true), dummy_session("10.0.0.1"));
        let ctx = AuthzContext { action: "read", identity: &id, resource_id: None };
        assert_eq!(policy.evaluate(&ctx).await, PolicyDecision::Abstain);
    }

    #[tokio::test]
    async fn ip_allow_list_denies_non_matching_ip() {
        let policy = IpAllowListPolicy::new(["10.0.0.1"]);
        let id  = identity(dummy_user(true), dummy_session("192.168.1.1"));
        let ctx = AuthzContext { action: "read", identity: &id, resource_id: None };
        assert_eq!(policy.evaluate(&ctx).await, PolicyDecision::Deny);
    }

    #[tokio::test]
    async fn ip_allow_list_abstains_on_empty_ip() {
        let policy = IpAllowListPolicy::new(["10.0.0.1"]);
        let id  = identity(dummy_user(true), dummy_session(""));
        let ctx = AuthzContext { action: "read", identity: &id, resource_id: None };
        assert_eq!(policy.evaluate(&ctx).await, PolicyDecision::Abstain);
    }

    // ── RequireEmailVerifiedPolicy ───────────────────────────────────────────

    #[tokio::test]
    async fn email_verified_policy_abstains_when_verified() {
        let policy = RequireEmailVerifiedPolicy::all_actions();
        let id  = identity(dummy_user(true), dummy_session("127.0.0.1"));
        let ctx = AuthzContext { action: "admin.delete", identity: &id, resource_id: None };
        assert_eq!(policy.evaluate(&ctx).await, PolicyDecision::Abstain);
    }

    #[tokio::test]
    async fn email_verified_policy_denies_when_not_verified() {
        let policy = RequireEmailVerifiedPolicy::all_actions();
        let id  = identity(dummy_user(false), dummy_session("127.0.0.1"));
        let ctx = AuthzContext { action: "admin.delete", identity: &id, resource_id: None };
        assert_eq!(policy.evaluate(&ctx).await, PolicyDecision::Deny);
    }

    #[tokio::test]
    async fn email_verified_abstains_for_non_matching_prefix() {
        let policy = RequireEmailVerifiedPolicy::for_prefix("admin.");
        let id  = identity(dummy_user(false), dummy_session("127.0.0.1"));
        let ctx = AuthzContext { action: "read.profile", identity: &id, resource_id: None };
        assert_eq!(policy.evaluate(&ctx).await, PolicyDecision::Abstain);
    }

    // ── OrgBoundaryPolicy ────────────────────────────────────────────────────

    #[tokio::test]
    async fn org_boundary_abstains_when_no_resource_id() {
        let policy = OrgBoundaryPolicy;
        let id  = identity(dummy_user(true), dummy_session("127.0.0.1"));
        let ctx = AuthzContext { action: "read", identity: &id, resource_id: None };
        assert_eq!(policy.evaluate(&ctx).await, PolicyDecision::Abstain);
    }

    #[tokio::test]
    async fn org_boundary_abstains_for_unscoped_resource() {
        let policy = OrgBoundaryPolicy;
        let id  = identity(dummy_user(true), dummy_session("127.0.0.1"));
        let ctx = AuthzContext { action: "read", identity: &id, resource_id: Some("global:thing") };
        assert_eq!(policy.evaluate(&ctx).await, PolicyDecision::Abstain);
    }
}
