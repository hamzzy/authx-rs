use uuid::Uuid;

use crate::models::{Session, User};

#[derive(Debug, Clone)]
pub enum AuthEvent {
    UserCreated { user: User },
    UserUpdated { user: User },
    SignIn      { user: User, session: Session },
    SignOut     { user_id: Uuid, session_id: Uuid },
    SessionExpired { session_id: Uuid, user_id: Uuid },
    PasswordChanged { user_id: Uuid },
    EmailVerified   { user_id: Uuid },
}

impl AuthEvent {
    pub fn name(&self) -> &'static str {
        match self {
            AuthEvent::UserCreated { .. }    => "user.created",
            AuthEvent::UserUpdated { .. }    => "user.updated",
            AuthEvent::SignIn { .. }         => "auth.sign_in",
            AuthEvent::SignOut { .. }        => "auth.sign_out",
            AuthEvent::SessionExpired { .. } => "session.expired",
            AuthEvent::PasswordChanged { .. }=> "auth.password_changed",
            AuthEvent::EmailVerified { .. }  => "auth.email_verified",
        }
    }
}
