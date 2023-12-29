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
use sqlx::query as SqlxQuery;

use crate::{
    errors::{AppError, AppErrorBuilder},
    types::DbPool,
};

pub const CHRONO_ACCESS_EXPIRED: Lazy<ChronoDuration> = Lazy::new(|| {
    let access_token_expired = env::var("TOKEN_DURATION_ACCESS")
        .unwrap()
        .parse::<i64>()
        .unwrap();
    ChronoDuration::seconds(access_token_expired)
});
pub const CHRONO_REFRESH_EXPIRED: Lazy<ChronoDuration> = Lazy::new(|| {
    let refresh_token_expired = env::var("TOKEN_DURATION_REFRESH")
        .unwrap()
        .parse::<i64>()
        .unwrap();
    ChronoDuration::seconds(refresh_token_expired)
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
            log::error!("[is_username_taken] Failed to execute query. {}", err);
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
            log::error!("[hashing_password] Failed to hash password. {}", err);
            AppErrorBuilder::new(
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                String::from("Failed to hash password."),
                Some(err.to_string()),
            )
            .internal_server_error()
        })?;

    Ok(hashed_password.to_string())
}
