//! Authentication service: password hashing, JWT, login, and user management.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::user::{CreateUser, User};

/// Maximum failed login attempts before account lockout.
const MAX_FAILED_ATTEMPTS: i32 = 3;

/// Lockout duration in minutes after exceeding max failed attempts.
const LOCKOUT_DURATION_MINUTES: i64 = 30;

/// JWT claims embedded in access and refresh tokens.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub user_id: String,
    pub role: String,
    pub token_type: String,
    pub exp: i64,
    pub iat: i64,
}

/// Token pair returned on successful login.
#[derive(Debug, Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

/// Hash a plaintext password with argon2id.
pub fn hash_password(password: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AppError::Internal(format!("Password hashing failed: {e}")))
}

/// Verify a plaintext password against a stored hash.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, AppError> {
    let parsed_hash =
        PasswordHash::new(hash).map_err(|e| AppError::Internal(format!("Invalid hash: {e}")))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Generate a JWT token pair (access + refresh).
pub fn generate_tokens(
    user: &User,
    jwt_secret: &str,
    access_expiry_secs: i64,
    refresh_expiry_secs: i64,
) -> Result<TokenPair, AppError> {
    let now = Utc::now();
    let encoding_key = EncodingKey::from_secret(jwt_secret.as_bytes());

    let access_claims = Claims {
        sub: user.username.clone(),
        user_id: user.id.to_string(),
        role: serde_json::to_string(&user.role)
            .unwrap_or_default()
            .trim_matches('"')
            .to_string(),
        token_type: "access".to_string(),
        exp: (now + Duration::seconds(access_expiry_secs)).timestamp(),
        iat: now.timestamp(),
    };

    let refresh_claims = Claims {
        sub: user.username.clone(),
        user_id: user.id.to_string(),
        role: access_claims.role.clone(),
        token_type: "refresh".to_string(),
        exp: (now + Duration::seconds(refresh_expiry_secs)).timestamp(),
        iat: now.timestamp(),
    };

    let access_token = jsonwebtoken::encode(&Header::default(), &access_claims, &encoding_key)
        .map_err(|e| AppError::Internal(format!("Token generation failed: {e}")))?;

    let refresh_token = jsonwebtoken::encode(&Header::default(), &refresh_claims, &encoding_key)
        .map_err(|e| AppError::Internal(format!("Token generation failed: {e}")))?;

    Ok(TokenPair {
        access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: access_expiry_secs,
    })
}

/// Validate a JWT and return the claims.
pub fn validate_token(token: &str, jwt_secret: &str) -> Result<Claims, AppError> {
    let decoding_key = DecodingKey::from_secret(jwt_secret.as_bytes());
    let validation = Validation::default();

    jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation)
        .map(|data| data.claims)
        .map_err(|_| AppError::Unauthorized)
}

/// Create a new user with hashed password.
pub async fn create_user(pool: &PgPool, input: &CreateUser) -> Result<User, AppError> {
    let password_hash = hash_password(&input.password)?;

    let user = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (username, email, password_hash, display_name, role)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        "#,
    )
    .bind(&input.username)
    .bind(&input.email)
    .bind(&password_hash)
    .bind(&input.display_name)
    .bind(&input.role)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref db_err) if db_err.is_unique_violation() => {
            AppError::Conflict("Username or email already exists".to_string())
        }
        _ => AppError::Database(e),
    })?;

    Ok(user)
}

/// Authenticate a user by username and password, returning a token pair.
pub async fn login(
    pool: &PgPool,
    username: &str,
    password: &str,
    jwt_secret: &str,
    access_expiry_secs: i64,
    refresh_expiry_secs: i64,
) -> Result<TokenPair, AppError> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await?
        .ok_or(AppError::Unauthorized)?;

    // Check account lockout
    if let Some(locked_until) = user.locked_until {
        if locked_until > Utc::now() {
            return Err(AppError::Unauthorized);
        }
    }

    // Check active status
    if !user.is_active {
        return Err(AppError::Unauthorized);
    }

    // Verify password
    if !verify_password(password, &user.password_hash)? {
        let new_attempts = user.failed_login_attempts + 1;
        if new_attempts >= MAX_FAILED_ATTEMPTS {
            let lock_until = Utc::now() + Duration::minutes(LOCKOUT_DURATION_MINUTES);
            sqlx::query(
                "UPDATE users SET failed_login_attempts = $1, locked_until = $2 WHERE id = $3",
            )
            .bind(new_attempts)
            .bind(lock_until)
            .bind(user.id)
            .execute(pool)
            .await?;
        } else {
            sqlx::query("UPDATE users SET failed_login_attempts = $1 WHERE id = $2")
                .bind(new_attempts)
                .bind(user.id)
                .execute(pool)
                .await?;
        }
        return Err(AppError::Unauthorized);
    }

    // Reset failed attempts on successful login
    sqlx::query(
        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = NOW() WHERE id = $1",
    )
    .bind(user.id)
    .execute(pool)
    .await?;

    generate_tokens(&user, jwt_secret, access_expiry_secs, refresh_expiry_secs)
}

/// Refresh an access token using a valid refresh token.
pub async fn refresh_token(
    pool: &PgPool,
    refresh_token_str: &str,
    jwt_secret: &str,
    access_expiry_secs: i64,
    refresh_expiry_secs: i64,
) -> Result<TokenPair, AppError> {
    let claims = validate_token(refresh_token_str, jwt_secret)?;

    if claims.token_type != "refresh" {
        return Err(AppError::Unauthorized);
    }

    let user_id: Uuid = claims
        .user_id
        .parse()
        .map_err(|_| AppError::Unauthorized)?;

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1 AND is_active = true")
        .bind(user_id)
        .fetch_optional(pool)
        .await?
        .ok_or(AppError::Unauthorized)?;

    generate_tokens(&user, jwt_secret, access_expiry_secs, refresh_expiry_secs)
}

/// Find a user by ID.
pub async fn find_user_by_id(pool: &PgPool, id: Uuid) -> Result<User, AppError> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::user::UserRole;

    #[test]
    fn password_hash_and_verify() {
        let password = "SecurePassword123!";
        let hash = hash_password(password).unwrap();
        assert_ne!(hash, password);
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("WrongPassword", &hash).unwrap());
    }

    #[test]
    fn token_generation_and_validation() {
        let user = User {
            id: Uuid::new_v4(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password_hash: "hash".to_string(),
            display_name: "Test".to_string(),
            role: UserRole::Developer,
            is_active: true,
            failed_login_attempts: 0,
            locked_until: None,
            last_login: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let secret = "test-secret-key-for-jwt";
        let tokens = generate_tokens(&user, secret, 900, 604800).unwrap();
        assert_eq!(tokens.token_type, "Bearer");
        assert_eq!(tokens.expires_in, 900);

        // Validate access token
        let claims = validate_token(&tokens.access_token, secret).unwrap();
        assert_eq!(claims.sub, "testuser");
        assert_eq!(claims.token_type, "access");
        assert_eq!(claims.role, "Developer");

        // Validate refresh token
        let refresh_claims = validate_token(&tokens.refresh_token, secret).unwrap();
        assert_eq!(refresh_claims.token_type, "refresh");
    }

    #[test]
    fn invalid_token_rejected() {
        let result = validate_token("garbage.token.here", "secret");
        assert!(result.is_err());
    }

    #[test]
    fn expired_token_rejected() {
        let user = User {
            id: Uuid::new_v4(),
            username: "test".to_string(),
            email: "t@t.com".to_string(),
            password_hash: "h".to_string(),
            display_name: "T".to_string(),
            role: UserRole::Developer,
            is_active: true,
            failed_login_attempts: 0,
            locked_until: None,
            last_login: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let secret = "test-secret";
        // Generate token that expired well beyond the 60s leeway window
        let tokens = generate_tokens(&user, secret, -3600, -3600).unwrap();
        let result = validate_token(&tokens.access_token, secret);
        assert!(result.is_err());
    }
}
