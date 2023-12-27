use std::{
    env,
    future::{ready, Ready},
};

use actix_web::{
    dev::Payload,
    http::{header as HttpHeader, StatusCode},
    FromRequest, HttpRequest,
};
use chrono::Utc;
use jsonwebtoken::{
    decode as JwtDecode, errors::ErrorKind as JwtErrorKind, Algorithm, DecodingKey, Validation,
};
use sqlx::query_as as SqlxQueryAs;

use crate::{
    errors::{AppError, AppErrorBuilder},
    types::{Claims, DbPool, UserRole}, users::models::User,
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