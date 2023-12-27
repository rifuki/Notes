use std::env;

use actix_web::{
    cookie::{time as CookieTime, Cookie, SameSite},
    http::StatusCode,
    HttpResponse,
};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use chrono::Duration as ChronoDuration;
use once_cell::sync::Lazy;
use serde_json::Value as JsonValue;
use sqlx::{query as SqlxQuery, query_as as SqlxQueryAs};

use crate::{
    errors::{AppError, AppErrorBuilder},
    jwt::JwtAuth,
    types::{DbPool, UserRole},
};

use super::models::User;

pub const CHRONO_ACCESS_EXPIRED: Lazy<ChronoDuration> = Lazy::new(|| {
    let access_token_expired = env::var("TOKEN_DURATION_ACCESS")
        .unwrap()
        .parse::<i64>()
        .unwrap();
    ChronoDuration::minutes(access_token_expired)
});
pub const CHRONO_REFRESH_EXPIRED: Lazy<ChronoDuration> = Lazy::new(|| {
    let refresh_token_expired = env::var("TOKEN_DURATION_REFRESH")
        .unwrap()
        .parse::<i64>()
        .unwrap();
    ChronoDuration::minutes(refresh_token_expired)
});

pub fn purge_expired_refresh_token_cookie(cookie_name: &str, message: &str) -> HttpResponse {
    let err_status_code = StatusCode::UNAUTHORIZED;
    let app_error_builder: AppErrorBuilder<bool> = AppErrorBuilder {
        code: err_status_code.as_u16(),
        message: message.to_string(),
        details: None,
    };
    let response_body: JsonValue = app_error_builder.into();
    let boo_cookie = Cookie::build(cookie_name, "")
        .secure(false)
        .same_site(SameSite::Strict)
        .http_only(true)
        .path("/")
        .expires(CookieTime::OffsetDateTime::now_utc())
        .finish();
    HttpResponse::build(err_status_code)
        .cookie(boo_cookie)
        .json(response_body)
}

pub async fn is_username_taken(username: &str, db_pool: &DbPool) -> Result<(), AppError> {
    let is_username_taken = SqlxQuery("SELECT 1 FROM users WHERE username = $1;")
        .bind(username)
        .fetch_optional(db_pool)
        .await
        .map_err(|err| {
            AppErrorBuilder::new(
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                String::from("Failed to check if username is taken."),
                Some(err.to_string()),
            )
            .internal_server_error()
        })?
        .is_some();

    if is_username_taken {
        return Err(AppErrorBuilder::<bool>::new(
            StatusCode::CONFLICT.as_u16(),
            String::from("Username is taken."),
            None,
        )
        .conflict()
        .into());
    }

    Ok(())
}

pub fn hashing_password(password: &str) -> Result<String, AppError> {
    let salt_string = SaltString::generate(OsRng);
    let argon2 = Argon2::default();

    let hashed_password = argon2
        .hash_password(password.as_ref(), &salt_string)
        .map_err(|err| {
            log::error!("failed to hash password: {}", err);
            AppErrorBuilder::new(
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                String::from("Failed to hash password."),
                Some(err.to_string()),
            )
            .internal_server_error()
        })?;

    Ok(hashed_password.to_string())
}

pub async fn validate_user_access_right(
    jwt_auth: &JwtAuth,
    db_pool: &DbPool,
    user_id: i32,
) -> Result<User, AppError> {
    // Get the authenticated user's from token.
    let auth_role = &jwt_auth.role;
    let auth_id = jwt_auth.id;

    // Verifying the existence of the searched user.
    let found_user = SqlxQueryAs::<_, User>("SELECT * FROM users WHERE id = $1;")
        .bind(user_id)
        .fetch_optional(db_pool)
        .await
        .map_err(|err| {
            log::error!("Failed to find user: {}", err);
            AppErrorBuilder::new(
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                format!("Failed to retrieve user with id: '{}'", user_id),
                Some(err.to_string()),
            )
            .internal_server_error()
        })?
        .ok_or_else(|| {
            // Temporary forbidden response for user not same identity.
            if auth_role != &UserRole::Admin.to_string() {
                return AppErrorBuilder::<bool>::new(
                    StatusCode::FORBIDDEN.as_u16(),
                    String::from("You're not allowed to access this endpoint. 1"),
                    None,
                )
                .forbidden();
            }

            AppErrorBuilder::<bool>::new(
                StatusCode::NOT_FOUND.as_u16(),
                format!("User with id: '{}' not found", user_id),
                None,
            )
            .not_found()
        })?;

    // Handle if not admin users or user with same identity.
    if auth_role == &UserRole::User.to_string() && auth_id != found_user.id {
        return Err(AppErrorBuilder::<bool>::new(
            StatusCode::FORBIDDEN.as_u16(),
            String::from("You're not allowed to access this endpoint. 2"),
            None,
        )
        .forbidden());
    }

    Ok(found_user)
}
