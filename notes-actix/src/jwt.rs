use std::future::{ready, Ready};

use actix_web::{dev::Payload, http::StatusCode, FromRequest, HttpRequest};
use sqlx::query_as as SqlxQueryAs;

use crate::{
    errors::{AppError, AppErrorBuilder},
    helpers::{decoding_claim_token, get_bearer_authorization_token},
    types::{ClaimsToken, DbPool, UserRole},
    users::models::User,
};

pub struct JwtAuth {
    pub id: i32,
    pub username: String,
    pub role: String,
    pub iat: i64,
    pub exp: i64,
    pub access_token: String,
}
impl FromRequest for JwtAuth {
    type Error = AppError;
    type Future = Ready<Result<Self, Self::Error>>;
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let bearer_token = match get_bearer_authorization_token(req) {
            Ok(token) => token,
            Err(err) => return ready(Err(err)),
        };

        let decoded_access_token = match decoding_claim_token(ClaimsToken::Access, bearer_token) {
            Ok(token) => token,
            Err(err) => {
                return ready(Err(err));
            }
        };

        ready(Ok(Self {
            id: decoded_access_token.id,
            username: decoded_access_token.username,
            role: decoded_access_token.role,
            iat: decoded_access_token.iat,
            exp: decoded_access_token.exp,
            access_token: bearer_token.to_owned(),
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
            log::error!(
                "[validate_user_access_right] Failed to retrieve user. {}",
                err
            );
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
