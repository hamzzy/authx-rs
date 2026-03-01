use chrono::Utc;
use uuid::Uuid;

use authx_core::{
    error::AuthError,
    models::{CreateSession, CreateUser, UpdateUser},
};

use super::MemoryStore;
use crate::ports::{SessionRepository, UserRepository};

fn store() -> MemoryStore {
    MemoryStore::new()
}

fn create_user_req(email: &str) -> CreateUser {
    CreateUser { email: email.to_owned(), metadata: None }
}

fn session_req(user_id: Uuid, token_hash: &str) -> CreateSession {
    CreateSession {
        user_id,
        token_hash:  token_hash.to_owned(),
        device_info: serde_json::Value::Null,
        ip_address:  "127.0.0.1".into(),
        org_id:      None,
        expires_at:  Utc::now() + chrono::Duration::hours(1),
    }
}

#[tokio::test]
async fn create_and_find_user_by_email() {
    let s = store();
    let user = UserRepository::create(&s, create_user_req("a@example.com")).await.unwrap();
    let found = UserRepository::find_by_email(&s, "a@example.com").await.unwrap();
    assert_eq!(found.unwrap().id, user.id);
}

#[tokio::test]
async fn duplicate_email_returns_error() {
    let s = store();
    UserRepository::create(&s, create_user_req("dup@example.com")).await.unwrap();
    let err = UserRepository::create(&s, create_user_req("dup@example.com")).await.unwrap_err();
    assert!(matches!(err, AuthError::EmailTaken));
}

#[tokio::test]
async fn find_nonexistent_user_returns_none() {
    let s = store();
    let found = UserRepository::find_by_id(&s, Uuid::new_v4()).await.unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn update_user_email_verified() {
    let s = store();
    let user = UserRepository::create(&s, create_user_req("u@example.com")).await.unwrap();
    assert!(!user.email_verified);

    let updated = UserRepository::update(
        &s,
        user.id,
        UpdateUser { email_verified: Some(true), ..Default::default() },
    )
    .await
    .unwrap();

    assert!(updated.email_verified);
}

#[tokio::test]
async fn delete_user_removes_record() {
    let s = store();
    let user = UserRepository::create(&s, create_user_req("del@example.com")).await.unwrap();
    UserRepository::delete(&s, user.id).await.unwrap();
    assert!(UserRepository::find_by_id(&s, user.id).await.unwrap().is_none());
}

#[tokio::test]
async fn create_and_find_session_by_token_hash() {
    let s = store();
    let user = UserRepository::create(&s, create_user_req("sess@example.com")).await.unwrap();
    let session = SessionRepository::create(&s, session_req(user.id, "hash123")).await.unwrap();

    let found = SessionRepository::find_by_token_hash(&s, "hash123").await.unwrap();
    assert_eq!(found.unwrap().id, session.id);
}

#[tokio::test]
async fn expired_session_not_returned() {
    let s = store();
    let user = UserRepository::create(&s, create_user_req("exp@example.com")).await.unwrap();

    let req = CreateSession {
        user_id:     user.id,
        token_hash:  "expiredhash".into(),
        device_info: serde_json::Value::Null,
        ip_address:  "127.0.0.1".into(),
        org_id:      None,
        expires_at:  Utc::now() - chrono::Duration::seconds(1),
    };
    SessionRepository::create(&s, req).await.unwrap();

    let found = SessionRepository::find_by_token_hash(&s, "expiredhash").await.unwrap();
    assert!(found.is_none(), "expired session should not be returned");
}

#[tokio::test]
async fn invalidate_removes_session() {
    let s = store();
    let user = UserRepository::create(&s, create_user_req("inv@example.com")).await.unwrap();
    let session = SessionRepository::create(&s, session_req(user.id, "tokenhash")).await.unwrap();

    SessionRepository::invalidate(&s, session.id).await.unwrap();
    assert!(SessionRepository::find_by_token_hash(&s, "tokenhash").await.unwrap().is_none());
}

#[tokio::test]
async fn invalidate_all_removes_all_user_sessions() {
    let s = store();
    let user = UserRepository::create(&s, create_user_req("all@example.com")).await.unwrap();
    SessionRepository::create(&s, session_req(user.id, "h1")).await.unwrap();
    SessionRepository::create(&s, session_req(user.id, "h2")).await.unwrap();

    SessionRepository::invalidate_all_for_user(&s, user.id).await.unwrap();

    let sessions = SessionRepository::find_by_user(&s, user.id).await.unwrap();
    assert!(sessions.is_empty());
}
