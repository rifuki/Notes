use std::env;

use actix_web::{
    cookie::{time as CookieTime, Cookie},
    http::StatusCode,
    HttpResponse,
};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use bb8::PooledConnection;
use bb8_redis::{redis::AsyncCommands, RedisConnectionManager};
use serde_json::Value as JsonValue;
use sqlx::query as SqlxQuery;

use crate::{
    errors::{AppError, AppErrorBuilder},
    helpers::check_is_https,
    types::{DbPool, RedisKey},
};

pub fn purge_expired_refresh_token_cookie(cookie_name: &str, message: &str) -> HttpResponse {
    let err_status_code = StatusCode::UNAUTHORIZED;
    let (secure, same_site) = check_is_https();
    let boo_cookie = Cookie::build(cookie_name, "")
        .secure(secure)
        .same_site(same_site)
        .http_only(true)
        .path("/")
        .expires(CookieTime::OffsetDateTime::now_utc())
        .finish();
    let app_error_builder: AppErrorBuilder<bool> = AppErrorBuilder {
        code: err_status_code.as_u16(),
        message: message.to_string(),
        details: None,
    };
    let response_body: JsonValue = app_error_builder.into();
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

pub async fn blacklisting_redis_token(
    redis_pool: &mut PooledConnection<'_, RedisConnectionManager>,
    redis_key: RedisKey,
    auth_id: i32,
    token: &str,
) -> Result<bool, AppError> {
    let key = match redis_key {
        RedisKey::BlacklistAccessToken => RedisKey::BlacklistAccessToken.to_string(),
        RedisKey::BlacklistRefreshToken => RedisKey::BlacklistRefreshToken.to_string(),
    };

    let key = format!("{}-{}", key, auth_id);
    let expired_token = match redis_key {
        RedisKey::BlacklistAccessToken => env::var("TOKEN_DURATION_ACCESS")
            .unwrap()
            .parse::<u64>()
            .unwrap(),
        RedisKey::BlacklistRefreshToken => env::var("TOKEN_DURATION_REFRESH")
            .unwrap()
            .parse::<u64>()
            .unwrap(),
    };

    let blacklisting_token = redis_pool
        .set_ex::<_, _, bool>(key, token, expired_token)
        .await
        .map_err(|err| {
            log::error!(
                "[blacklisting_access_token] Error setting token to redis. {}",
                err
            );
            AppErrorBuilder::new(
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                String::from("Failed to set token to redis."),
                Some(err.to_string()),
            )
            .internal_server_error()
        })?;

    if !blacklisting_token {
        return Err(AppErrorBuilder::<bool>::new(
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            String::from("Failed to blacklisting token."),
            None,
        )
        .internal_server_error());
    }

    Ok(blacklisting_token)
}
