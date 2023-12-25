use std::env;

use actix_web::{
    cookie::{time as CookieTime, Cookie, SameSite},
    http::StatusCode,
    HttpResponse,
};
use chrono::Duration as ChronoDuration;
use once_cell::sync::Lazy;
use serde_json::Value as JsonValue;

use crate::errors::AppErrorBuilder;

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
