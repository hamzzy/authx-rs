use serde::{Deserialize, Serialize};

use crate::models::{Membership, Organization, Session, User};

/// Request-scoped resolved identity — user + active org context.
///
/// Constructed by the session middleware and passed to route handlers
/// via framework extractors. Never persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub user:               User,
    pub session:            Session,
    pub active_org:         Option<Organization>,
    pub active_membership:  Option<Membership>,
}

impl Identity {
    pub fn new(user: User, session: Session) -> Self {
        Self { user, session, active_org: None, active_membership: None }
    }

    pub fn with_org(mut self, org: Organization, membership: Membership) -> Self {
        self.active_org        = Some(org);
        self.active_membership = Some(membership);
        self
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        self.active_membership
            .as_ref()
            .map(|m| m.role.permissions.iter().any(|p| p == permission))
            .unwrap_or(false)
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.active_membership
            .as_ref()
            .map(|m| m.role.name == role)
            .unwrap_or(false)
    }
}
