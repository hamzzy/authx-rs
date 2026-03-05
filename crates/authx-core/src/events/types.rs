use uuid::Uuid;

use crate::models::{Membership, Session, User};

#[derive(Debug, Clone)]
pub enum AuthEvent {
    UserCreated {
        user: User,
    },
    UserUpdated {
        user: User,
    },
    SignIn {
        user: User,
        session: Session,
    },
    SignOut {
        user_id: Uuid,
        session_id: Uuid,
    },
    SessionExpired {
        session_id: Uuid,
        user_id: Uuid,
    },
    PasswordChanged {
        user_id: Uuid,
    },
    EmailVerified {
        user_id: Uuid,
    },
    OAuthLinked {
        user_id: Uuid,
        provider: String,
    },
    InviteAccepted {
        membership: Membership,
    },
    // OIDC administration events
    OidcClientCreated {
        client_id: String,
        name: String,
        actor_id: Option<Uuid>,
    },
    OidcClientDeleted {
        client_id: String,
        actor_id: Option<Uuid>,
    },
    OidcFederationProviderCreated {
        provider_id: Uuid,
        name: String,
        actor_id: Option<Uuid>,
    },
    OidcFederationProviderDeleted {
        provider_id: Uuid,
        actor_id: Option<Uuid>,
    },
}

impl AuthEvent {
    pub fn name(&self) -> &'static str {
        match self {
            AuthEvent::UserCreated { .. } => "user.created",
            AuthEvent::UserUpdated { .. } => "user.updated",
            AuthEvent::SignIn { .. } => "auth.sign_in",
            AuthEvent::SignOut { .. } => "auth.sign_out",
            AuthEvent::SessionExpired { .. } => "session.expired",
            AuthEvent::PasswordChanged { .. } => "auth.password_changed",
            AuthEvent::EmailVerified { .. } => "auth.email_verified",
            AuthEvent::OAuthLinked { .. } => "auth.oauth_linked",
            AuthEvent::InviteAccepted { .. } => "org.invite_accepted",
            AuthEvent::OidcClientCreated { .. } => "oidc.client_created",
            AuthEvent::OidcClientDeleted { .. } => "oidc.client_deleted",
            AuthEvent::OidcFederationProviderCreated { .. } => "oidc.federation_provider_created",
            AuthEvent::OidcFederationProviderDeleted { .. } => "oidc.federation_provider_deleted",
        }
    }
}
