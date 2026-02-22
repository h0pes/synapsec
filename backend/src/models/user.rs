//! User model with role-based access control.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "user_role")]
pub enum UserRole {
    #[sqlx(rename = "Platform_Admin")]
    PlatformAdmin,
    #[sqlx(rename = "AppSec_Analyst")]
    AppSecAnalyst,
    #[sqlx(rename = "AppSec_Manager")]
    AppSecManager,
    Developer,
    Executive,
    Auditor,
    #[sqlx(rename = "API_Service_Account")]
    ApiServiceAccount,
}

/// Full user row from database (includes password_hash — never serialize to API).
#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub display_name: String,
    pub role: UserRole,
    pub is_active: bool,
    pub failed_login_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub last_login: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// User response DTO — excludes password_hash and internal fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub display_name: String,
    pub role: UserRole,
    pub is_active: bool,
    pub last_login: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            username: u.username,
            email: u.email,
            display_name: u.display_name,
            role: u.role,
            is_active: u.is_active,
            last_login: u.last_login,
            created_at: u.created_at,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateUser {
    pub username: String,
    pub email: String,
    pub password: String,
    pub display_name: String,
    pub role: UserRole,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct UpdateUser {
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub role: Option<UserRole>,
    pub is_active: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_role_serialization() {
        let role = UserRole::AppSecAnalyst;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, "\"AppSecAnalyst\"");
    }

    #[test]
    fn user_response_excludes_password() {
        let json = serde_json::to_string(&UserResponse {
            id: Uuid::nil(),
            username: "admin".to_string(),
            email: "admin@test.com".to_string(),
            display_name: "Admin".to_string(),
            role: UserRole::PlatformAdmin,
            is_active: true,
            last_login: None,
            created_at: Utc::now(),
        })
        .unwrap();
        assert!(!json.contains("password"));
        assert!(!json.contains("hash"));
    }

    #[test]
    fn user_to_response_conversion() {
        let user = User {
            id: Uuid::nil(),
            username: "test".to_string(),
            email: "test@test.com".to_string(),
            password_hash: "secret_hash".to_string(),
            display_name: "Test".to_string(),
            role: UserRole::Developer,
            is_active: true,
            failed_login_attempts: 0,
            locked_until: None,
            last_login: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let response: UserResponse = user.into();
        assert_eq!(response.username, "test");
        assert_eq!(response.role, UserRole::Developer);
    }
}
