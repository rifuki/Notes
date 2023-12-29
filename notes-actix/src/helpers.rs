use std::env;

use actix_web::{
    cookie::SameSite,
    http::{header as HttpHeader, StatusCode},
    HttpRequest,
};
use bb8::PooledConnection;
use bb8_redis::{redis::AsyncCommands, RedisConnectionManager};
use chrono::Utc;
use jsonwebtoken::{
    decode as JwtDecode, encode as JwtEncode, errors::ErrorKind as JwtErrorKind, Algorithm,
    DecodingKey, EncodingKey, Header, Validation,
};

use crate::{
    errors::{AppError, AppErrorBuilder},
    types::{Claims, ClaimsToken, RedisKey},
    utils::{get_current_utc_timestamp, CHRONO_ACCESS_DURATION, CHRONO_REFRESH_DURATION},
};

pub async fn is_access_token_blacklisted(
    auth_id: i32,
    mut redis_pool: PooledConnection<'_, RedisConnectionManager>,
) -> Result<(), AppError> {
    let key_redis = format!("{}-{}", RedisKey::BlacklistAccessToken.to_string(), auth_id);
    let is_token_blacklisted = redis_pool.get::<_, String>(key_redis).await;
    if is_token_blacklisted.is_ok() {
        return Err(AppErrorBuilder::<bool>::new(
            StatusCode::UNAUTHORIZED.as_u16(),
            String::from("You're not authorized to access this endpoint."),
            None,
        )
        .unauthorized());
    }
    Ok(())
}

pub fn check_is_https() -> (bool, SameSite) {
    let is_https = env::var("HTTPS")
        .unwrap_or(String::from("false"))
        .to_lowercase()
        .parse::<bool>()
        .unwrap();

    let mut same_site = SameSite::Strict;
    if is_https {
        same_site = SameSite::None;
    }

    (is_https, same_site)
}

pub fn get_bearer_authorization_token(req: &HttpRequest) -> Result<&str, AppError> {
    let auth_header = req.headers().get(HttpHeader::AUTHORIZATION);
    if auth_header.is_none() {
        return Err(AppErrorBuilder::<bool>::new(
            StatusCode::UNAUTHORIZED.as_u16(),
            // String::from("Authorization header not found."),
            String::from("You're not authorized to access this endpoint."),
            None,
        )
        .unauthorized());
    }

    let auth_header_value = auth_header.unwrap().to_str().map_err(|_| {
        AppErrorBuilder::<bool>::new(
            StatusCode::UNAUTHORIZED.as_u16(),
            String::from("Invalid authorization header."),
            None,
        )
        .unauthorized()
    })?;

    if !auth_header_value.starts_with("Bearer ") {
        return Err(AppErrorBuilder::<bool>::new(
            StatusCode::UNAUTHORIZED.as_u16(),
            String::from("Invalid bearer token format."),
            None,
        )
        .unauthorized());
    }
    let bearer_token_parts = auth_header_value.split_whitespace().collect::<Vec<&str>>();
    if bearer_token_parts.len() != 2 {
        return Err(AppErrorBuilder::<bool>::new(
            StatusCode::UNAUTHORIZED.as_u16(),
            String::from("Invalid bearer token."),
            None,
        )
        .unauthorized());
    }
    let bearer_token = bearer_token_parts[1];

    Ok(bearer_token)
}

pub fn encoding_claim_token(
    token: ClaimsToken,
    id: i32,
    username: &str,
    role: &str,
) -> Result<String, AppError> {
    let chrono_token_duration = match token {
        ClaimsToken::Access => *CHRONO_ACCESS_DURATION,
        ClaimsToken::Refresh => *CHRONO_REFRESH_DURATION,
    };
    let exp_token = Utc::now()
        .naive_utc()
        .checked_add_signed(chrono_token_duration)
        .ok_or_else(|| {
            log::error!("[exp_token] Failed to calculate claim token expiration.");
            AppErrorBuilder::<bool>::new(
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                String::from("Failed to calculate claim token expiration."),
                None,
            )
            .internal_server_error()
        })?
        .timestamp();

    let claims_token = Claims {
        id: id,
        username: username.to_owned(),
        role: role.to_string(),
        iat: get_current_utc_timestamp(),
        exp: exp_token,
    };

    let secret_key = match token {
        ClaimsToken::Access => env::var("SECRET_KEY_ACCESS").unwrap(),
        ClaimsToken::Refresh => env::var("SECRET_KEY_REFRESH").unwrap(),
    };

    let encoded_token = JwtEncode(
        &Header::default(),
        &claims_token,
        &EncodingKey::from_secret(&secret_key.as_ref()),
    )
    .map_err(|err| {
        log::error!("[encoded_token] Failed to encode token. {}", err);
        AppErrorBuilder::new(
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            String::from("Failed to encode token."),
            Some(err.to_string()),
        )
        .internal_server_error()
    })?;

    Ok(encoded_token)
}

pub fn decoding_claim_token(token: ClaimsToken, refresh_token: &str) -> Result<Claims, AppError> {
    let secret_key = match token {
        ClaimsToken::Access => env::var("SECRET_KEY_ACCESS").unwrap(),
        ClaimsToken::Refresh => env::var("SECRET_KEY_REFRESH").unwrap(),
    };
    let error_message = match token {
        ClaimsToken::Access => String::from(
            "Your access token has expired. Please refresh your access token or log in again.",
        ),
        ClaimsToken::Refresh => String::from("Your session has expired. Please log in again."),
    };

    let decoded_claim_token = JwtDecode::<Claims>(
        &refresh_token,
        &DecodingKey::from_secret(&secret_key.as_ref()),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|err| match err.kind() {
        JwtErrorKind::ExpiredSignature => AppErrorBuilder::<bool>::new(
            StatusCode::UNAUTHORIZED.as_u16(),
            format!("{} 2", error_message),
            None,
        )
        .unauthorized(),
        _ => AppErrorBuilder::new(
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            String::from("Your token is broken. Please refresh or log in again."),
            Some(err.to_string()),
        )
        .unauthorized(),
    })?
    .claims;

    if get_current_utc_timestamp() > decoded_claim_token.exp {
        return Err(AppErrorBuilder::<bool>::new(
            StatusCode::UNAUTHORIZED.as_u16(),
            format!("{} 1", error_message),
            None,
        )
        .unauthorized());
    }

    Ok(decoded_claim_token)
}
