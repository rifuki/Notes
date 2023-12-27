use actix_web::{
    dev::Payload,
    http::{header as HttpHeader, StatusCode},
    FromRequest, HttpRequest,
};
use chrono::Utc;
use jsonwebtoken::{
    decode as JwtDecode, errors::ErrorKind as JwtErrorKind, Algorithm, DecodingKey, Validation,
};
use std::{
    env,
    future::{ready, Ready},
};

use crate::{
    errors::{AppError, AppErrorBuilder},
    types::Claims,
};

pub struct JwtAuth {
    pub id: i32,
    pub username: String,
    pub role: String,
    pub iat: i64,
    pub exp: i64,
}
impl FromRequest for JwtAuth {
    type Error = AppError;
    type Future = Ready<Result<Self, Self::Error>>;
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let auth_header = req.headers().get(HttpHeader::AUTHORIZATION);
        if auth_header.is_none() {
            return ready(Err(AppErrorBuilder::<bool>::new(
                StatusCode::UNAUTHORIZED.as_u16(),
                // String::from("Authorization header not found."),
                String::from("You're not authorized to access this endpoint."),
                None,
            )
            .unauthorized()));
        }
        let auth_header_value = auth_header.map_or("", |hv| hv.to_str().unwrap_or_default());
        if !auth_header_value.starts_with("Bearer ") {
            return ready(Err(AppErrorBuilder::<bool>::new(
                StatusCode::UNAUTHORIZED.as_u16(),
                String::from("Invalid bearer token format."),
                None,
            )
            .unauthorized()));
        }
        let bearer_token_parts = auth_header_value.split_whitespace().collect::<Vec<&str>>();
        if bearer_token_parts.len() != 2 {
            return ready(Err(AppErrorBuilder::<bool>::new(
                StatusCode::UNAUTHORIZED.as_u16(),
                String::from("Invalid bearer token."),
                None,
            )
            .unauthorized()));
        }
        let bearer_token = bearer_token_parts[1];

        let secret_key_access = env::var("SECRET_KEY_ACCESS").unwrap();
        let decoded_access_token = JwtDecode::<Claims>(
            bearer_token,
            &DecodingKey::from_secret(&secret_key_access.as_ref()),
            &Validation::new(Algorithm::HS256),
        );
        if let Err(error) = &decoded_access_token {
            match error.kind() {
                JwtErrorKind::ExpiredSignature => {
                    return ready(Err(AppErrorBuilder::<bool>::new(
                        StatusCode::UNAUTHORIZED.as_u16(),
                        String::from(
                            "Your Access token has expired. Please refresh your access token or log in again. 2",
                        ),
                        None,
                    )
                    .unauthorized()));
                }
                _ => {
                    return ready(Err(AppErrorBuilder::new(
                        StatusCode::UNAUTHORIZED.as_u16(),
                        String::from("Your acess token is broken. Please log in again."),
                        Some(error.to_string()),
                    )
                    .unauthorized()))
                }
            }
        }
        let access_token = decoded_access_token.clone().unwrap().claims;
        let access_token_exp = access_token.exp;
        if Utc::now().naive_utc().timestamp() > access_token_exp {
            return ready(Err(AppErrorBuilder::<bool>::new(
                StatusCode::UNAUTHORIZED.as_u16(),
                String::from(
                    "Your Access token has expired. Please refresh your access token or log in again. 1",
                ),
                None,
            )
            .internal_server_error()));
        }

        ready(Ok(Self {
            id: access_token.id,
            username: access_token.username,
            role: access_token.role,
            iat: access_token.iat,
            exp: access_token.exp,
        }))
    }
}
