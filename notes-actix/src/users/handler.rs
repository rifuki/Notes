use std::env;

use actix_web::{
    cookie::{time as CookieTime, Cookie, SameSite},
    http::StatusCode,
    web, HttpRequest, HttpResponse,
};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use chrono::Utc;
use jsonwebtoken::{
    decode as JwtDecode, encode as JwtEncode, errors::ErrorKind as JwtErrorKind, Algorithm,
    DecodingKey, EncodingKey, Header, Validation,
};
use serde_json::json;
use sqlx::{query as SqlxQuery, query_as as SqlxQueryAs};
use validator::Validate;

use crate::{
    errors::{AppError, AppErrorBuilder},
    // jwt::JwtAuth,
    types::{AppState, Claims},
    users::{
        helpers::{
            purge_expired_refresh_token_cookie, CHRONO_ACCESS_EXPIRED, CHRONO_REFRESH_EXPIRED,
        },
        models::{User, UserClaims, UserLoginPayload, UserRegisterPayload, UserUpdatePayload},
        types::{DeleteUserPathParams, GetUserPathParams, UpdateUserPathParams},
    },
    utils::get_current_utc_timestamp,
};

use super::helpers::is_username_taken;

/// Authenticates user credentials and generates access tokens for accessing protected routes.
///
/// This endpoint allows users to log in by providing their username and password.
///
/// # Arguments
///
/// * `app_state`: Shared application state containing the database connection pool.
/// * `json_request`: JSON payload containing the user's credentials.
///
/// # Returns
///
/// Returns a `Result` containing an `HttpResponse` on successful login or an `AppError` on failure.
///
/// ## Request Body
///
/// Expects a JSON object with the following fields:
/// - `username`: User's username.
/// - `password`: User's password.
///
/// ## Responses
///
/// - **200 OK:** Successfully logged in.
///
/// - **401 Unauthorized:** Invalid credentials provided.
///
/// - **500 Internal Server Error:** Failed to process the request due to server issues.
///
/// Note: Ensure the JSON payload contains both `username` and `password` fields for a successful login.
#[utoipa::path(
    post,
    tag = "Authentication",
    path = "/api/v1/login",
    request_body(content = UserLoginPayload, description = "", content_type = "application/json"),
    responses(
        (status = 200, description = "User successfully logged in.", body = UserClaims,
            example = json!({
                "accessToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6NSwidXNlcm5hbWUiOiJqb2huIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MDM1MjI5NzIsImV4cCI6MTcwMzUyMzAzMn0.4Cg6WrMDYjpLHbBBffToWbzOdZjvwRxtXQvecFhKe9Q",
                "code": 200,
                "message": "Successfully logged in.",
                "user": {
                    "id": 1,
                    "role": "user",
                    "username": "john"
                }
            })
        ),
        (status = 401, description = "Unauthorized - invalid username or password.", body = isize, content_type = "application/json",
            example = json!({
                "code": 401,
                "message": "Invalid username or password. Please try again."
            })
        ),
        (status = 422, description = "The response indicates a validation error due to invalid data submitted. Details regarding specific validation requirements for `username`, `password`, and `confirmPassword` fields are provided, helping identify the reasons for failure.", body = isize, content_type = "application/json",
            example = json!({
                "code": 422,
                "details": {
                    "password": [
                        "Password length must be at least 8 characters long.",
                        "Password must be at least one special character.",
                        "Password must contain at least one uppercase letter, one lowercase letter, one digit, one special characters, is at least 8 characters long, and does not contain spaces."
                    ],
                    "username": [
                        "Username length must be between 1 to 50 characters long.",
                        "Username must consist of alphanumeric characters and be at least 1 characters long."
                    ]
                },
                "message": "Validation Error"
            })
        ),
        (status = 500, description = "Internal Server Error - Failed to process the request due to an unexpected server error.")
    )
)]
pub async fn auth_login(
    app_state: web::Data<AppState>,
    request_body: web::Json<UserLoginPayload>,
) -> Result<HttpResponse, AppError> {
    let payload = request_body.into_inner();
    if let Err(err) = payload.validate() {
        return Err(err.into());
    }
    let db_pool = &app_state.get_ref().db_pool;

    // Checking is username auth stored?.
    let stored_user = SqlxQueryAs::<_, User>("SELECT * FROM users WHERE username = $1")
        .bind(&payload.username)
        .fetch_optional(db_pool)
        .await
        .map_err(|err| {
            AppErrorBuilder::new(
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                String::from("Error fetching stored user."),
                Some(err.to_string()),
            )
            .internal_server_error()
        })?
        .ok_or_else(|| {
            AppErrorBuilder::<bool>::new(
                StatusCode::NOT_FOUND.as_u16(),
                String::from("Invalid username or password. Please try again."),
                None,
            )
            .unauthorized()
        })?;

    // Comparing stored with payload password.
    let parsed_stored_password = PasswordHash::new(&stored_user.password).unwrap();
    let argon2 = Argon2::default();
    let _verify_password = argon2
        .verify_password(&payload.password.as_ref(), &parsed_stored_password)
        .map_err(|_| {
            AppErrorBuilder::<bool>::new(
                StatusCode::UNAUTHORIZED.as_u16(),
                format!("Invalid username or password. Please try again."),
                None,
            )
            .unauthorized()
        })?;

    let claims = Claims {
        id: stored_user.id,
        username: stored_user.username.to_owned(),
        role: stored_user.role,
        iat: get_current_utc_timestamp(),
        exp: 0,
    };
    // Create a new JWT access token.
    let secret_key_access = env::var("SECRET_KEY_ACCESS").unwrap();
    let claims_access_token = Claims {
        exp: Utc::now()
            .naive_utc()
            .checked_add_signed(*CHRONO_ACCESS_EXPIRED)
            .ok_or_else(|| {
                AppErrorBuilder::<bool>::new(
                    StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    String::from("Failed to calculate eefresh token expiration."),
                    None,
                )
                .internal_server_error()
            })?
            .timestamp(),
        ..claims.clone()
    };
    let encoded_access_token = JwtEncode(
        &Header::default(),
        &claims_access_token,
        &EncodingKey::from_secret(&secret_key_access.as_ref()),
    )
    .map_err(|err| {
        AppErrorBuilder::new(
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            String::from("Failed to encode access token."),
            Some(err.to_string()),
        )
        .internal_server_error()
    })?;
    // Create a new JWT refresh token.
    let secret_key_refresh = env::var("SECRET_KEY_REFRESH").unwrap();
    let claims_refresh_token = Claims {
        exp: Utc::now()
            .naive_utc()
            .checked_add_signed(*CHRONO_REFRESH_EXPIRED)
            .ok_or_else(|| {
                AppErrorBuilder::<bool>::new(
                    StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    String::from("Failed to calculate refresh token expiration."),
                    None,
                )
                .internal_server_error()
            })?
            .timestamp(),
        ..claims
    };
    let encoded_refresh_token = JwtEncode(
        &Header::default(),
        &claims_refresh_token,
        &EncodingKey::from_secret(&secret_key_refresh.as_ref()),
    )
    .map_err(|err| {
        AppErrorBuilder::new(
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            String::from("Failed to encode refresh token."),
            Some(err.to_string()),
        )
        .internal_server_error()
    })?;

    // Storing encoded refresh token to database.
    let user_updated_refresh_token = SqlxQueryAs::<_, UserClaims>(
        "UPDATE users SET refresh_token = $1 WHERE id = $2 RETURNING *;",
    )
    .bind(&encoded_refresh_token)
    .bind(&stored_user.id)
    .fetch_one(db_pool)
    .await
    .map_err(|err| {
        AppErrorBuilder::new(
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            String::from("Failed to set refresh token."),
            Some(err.to_string()),
        )
        .internal_server_error()
    })?;

    // Final http response and giving a cookie 🍪🥰.
    let status_code = StatusCode::OK;
    let response_body = json!({
        "code": status_code.as_u16(),
        "message": "Successfully logged in.",
        "user": user_updated_refresh_token,
        "accessToken": encoded_access_token,
    });
    let yay_cookie = Cookie::build("refreshToken", &encoded_refresh_token)
        .secure(false)
        .same_site(SameSite::Strict)
        .http_only(true)
        .path("/")
        .finish();
    Ok(HttpResponse::build(status_code)
        .cookie(yay_cookie)
        .json(response_body))
}

/// Refreshes the user's authorization token to maintain access to protected routes.
///
/// This endpoint generates a new access token using a valid refresh token, allowing users to extend their session and access protected routes without re-authentication.
///
/// # Arguments
///
/// * `req`: The HTTP request object containing the refresh token in the cookie.
/// * `app_state`: Shared application state containing the database connection pool.
///
/// # Returns
///
/// Returns a `Result` containing an `HttpResponse` on successful token refresh or an `AppError` on failure.
///
/// ## Responses
///
/// - **200 OK:** Successfully refreshed authorization. Returns an updated access token and user details.
///
/// - **401 Unauthorized:** Session expiration or invalid refresh token. User needs to re-authenticate.
///
/// - **500 Internal Server Error:** Failed to process the request due to an unexpected server error.
///
/// Note: This endpoint requires a valid refresh token in the cookie to generate a new access token.
#[utoipa::path(
    get,
    tag = "Authentication",
    path = "/api/v1/refresh",
    responses(
        (status = 200, description = "Successfully refreshed authorization.", body = UserClaims,
            example = json!({
                "accessToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6NSwidXNlcm5hbWUiOiJqb2huIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MDM1MjQ4MTcsImV4cCI6MTcwMzUyNDg3N30.LL4XRTLGL0C5syPJ5PwrX3cLbgy6659aUuSv76MO4Xk",
                "code": 200,
                "message": "Authorization refreshed successfully.",
                "user": {
                    "id": 1,
                    "role": "user",
                    "username": "john"
                }
            })
        ),
        (status = 401, description = "Unauthorized - Session expiration or invalid refresh token.", body = isize, content_type = "application/json", 
            example = json!({
                "code": 401,
                "message": "Your session has expired. Please log in again."
            })
        ),
        (status = 500, description = "Internal Server Error - Failed to process the request due to an unexpected server error.")
    )
)]
pub async fn auth_refresh(
    req: HttpRequest,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    // Checking if cookie refresh token is set.
    let refresh_token_cookie = req
        .cookie("refreshToken")
        .map(|cookie| cookie.value().to_string())
        .ok_or_else(|| {
            AppErrorBuilder::<bool>::new(
                StatusCode::UNAUTHORIZED.as_u16(),
                String::from("You're not authorized. Please log in again."),
                None,
            )
            .unauthorized()
        })?;

    // Decoding refresh token from cookie.
    let secret_key_refresh = env::var("SECRET_KEY_REFRESH").unwrap();
    let decoded_refresh_token = JwtDecode::<Claims>(
        &refresh_token_cookie,
        &DecodingKey::from_secret(&secret_key_refresh.as_ref()),
        &Validation::new(Algorithm::HS256),
    )
    // Handle refresh token expired.
    .map_err(|err| match err.kind() {
        JwtErrorKind::ExpiredSignature => AppErrorBuilder::<bool>::new(
            StatusCode::UNAUTHORIZED.as_u16(),
            String::from("Your session has expired. Please log in again."),
            None,
        )
        .unauthorized(),
        _ => AppErrorBuilder::new(
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            String::from("Refresh token is broken. Please log in again."),
            Some(err.to_string()),
        )
        .unauthorized(),
    })?;
    if get_current_utc_timestamp() > decoded_refresh_token.claims.exp {
        return Err(AppErrorBuilder::<bool>::new(
            StatusCode::UNAUTHORIZED.as_u16(),
            String::from("Your session has expired. Please log in again."),
            None,
        )
        .unauthorized());
    }

    // Getting stored_user based on refresh token.
    let db_pool = &app_state.get_ref().db_pool;
    let stored_user = SqlxQueryAs::<_, UserClaims>("SELECT * FROM users WHERE refresh_token = $1")
        .bind(refresh_token_cookie)
        .fetch_optional(db_pool)
        .await
        .map_err(|err| {
            AppErrorBuilder::new(
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                String::from("Error fetching stored user."),
                Some(err.to_string()),
            )
            .internal_server_error()
        })?
        .ok_or_else(|| {
            AppErrorBuilder::<bool>::new(
                StatusCode::UNAUTHORIZED.as_u16(),
                String::from("You're not authorized. Please log in again."),
                None,
            )
            .unauthorized()
        })?;

    // Generate a new JWT access token.
    let claims_access_token = Claims {
        id: stored_user.id,
        username: stored_user.username.to_owned(),
        role: stored_user.role.clone(),
        iat: get_current_utc_timestamp(),
        exp: Utc::now()
            .naive_utc()
            .checked_add_signed(*CHRONO_ACCESS_EXPIRED)
            .ok_or_else(|| {
                AppErrorBuilder::<bool>::new(
                    StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    String::from("Failed to calculate refresh token expiration."),
                    None,
                )
                .internal_server_error()
            })?
            .timestamp(),
    };
    let secret_key_access = env::var("SECRET_KEY_ACCESS").unwrap();
    let encoded_access_token = JwtEncode(
        &Header::default(),
        &claims_access_token,
        &EncodingKey::from_secret(&secret_key_access.as_ref()),
    )
    .map_err(|e| {
        AppErrorBuilder::new(
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            String::from("Failed to encode access token."),
            Some(e.to_string()),
        )
        .internal_server_error()
    })?;

    // Final http response.
    let status_code = StatusCode::OK;
    let response_body = json!({
        "code": status_code.as_u16(),
        "message": "Authorization refreshed successfully.",
        "user": stored_user,
        "accessToken": encoded_access_token,
    });
    Ok(HttpResponse::build(status_code).json(response_body))
}

/// Logout the user, revoking access and deleting the refresh token from the database.
///
/// This endpoint is used to facilitate the logout process for a user. Upon successful logout, the user's access is revoked, and their associated refresh token is deleted from the database. Additionally, the cookie containing the refresh token is expired.
///
/// # Arguments
///
/// * `app_state`: Shared application state containing the database connection pool.
/// * `req`: The HTTP request object containing the refresh token in the cookie.
///
/// # Returns
///
/// Returns a `Result` containing an `HttpResponse` on successful logout or an `AppError` on failure.
///
/// ## Responses
///
/// - **200 OK:** Successful logout. Returns details of the logged-out user with a null refresh token.
///
/// - **401 Unauthorized:**
///   - `Cookie 'refreshToken' is missing:` The cookie containing the refresh token is missing, indicating that the user is already logged out.
///   - `Refresh token is missing in the database:` The refresh token is not found in the database, indicating that the user is already logged out.
///   - `Refresh token has expired by manual comparison:` The refresh token is determined to be expired through manual comparison.
///   - `Refresh token has expired based on JwtErrorKind:` The refresh token is expired based on JwtErrorKind.
///
/// - **500 Internal Server Error:** Failed to process the request due to an unexpected server error.
///
/// Note: To perform the logout operation, this endpoint requires a valid refresh token in the cookie.
#[utoipa::path(
    get,
    tag = "Authentication",
    path = "/api/v1/logout",
    responses(
        (status = 200, description = "Succesful logout.", body = User, 
            example = json!({
                "code": 200,
                "message": "Successfully logged out.",
                "user": {
                    "id": 1,
                    "refreshToken": null,
                    "username": "john"
                }
            })
        ),
        (status = 200, description = "", body = isize, content_type = "application/json", examples(
            ("Cookie `refreshToken` is missing" = (
                value = json!({
                    "code": 401,
                    "message": "You're already logged out. 1"
                })
            )),
            ("Refresh token is misssing in database" = (
                value = json!({
                    "code": 401,
                    "message": "You're already logged out. 2"
                })
            )),
            ("Refresh token is expired manual comparison" = (
                value = json!({
                    "code": 401,
                    "message": "You're already logged out. 3"
                })
            )),
            ("Refresh token is expired on JwtErrorKind" = (
                value = json!({
                    "code": 401,
                    "message": "You're already logged out. 4"
                })
            ))
        )),
        (status = 500, description = "Internal Server Error - Failed to process the request due to an unexpected server error.")
    ),
)]
pub async fn auth_logout(
    app_state: web::Data<AppState>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let refresh_token_name = "refreshToken";
    // Getting the refresh token from the cookie.
    let refresh_token_cookie = req
        .cookie(refresh_token_name)
        .map(|cookie| cookie.value().to_string())
        .ok_or_else(|| {
            AppErrorBuilder::<bool>::new(
                StatusCode::UNAUTHORIZED.as_u16(),
                String::from("You're already logged out. 1"),
                None,
            )
            .unauthorized()
        })?;

    // Set the refresh token to null in db.
    let db_pool = &app_state.get_ref().db_pool;
    let set_refresh_token_null = SqlxQueryAs::<_, User>(
        "UPDATE users SET refresh_token = NULL WHERE refresh_token = $1 RETURNING *;",
    )
    .bind(&refresh_token_cookie)
    .fetch_optional(db_pool)
    .await
    .map_err(|err| {
        AppErrorBuilder::new(
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            String::from("Failed to set refresh token."),
            Some(err.to_string()),
        )
        .internal_server_error()
    })?;
    // If refresh token in db is not found, return error 🚮🍪.
    if let None = set_refresh_token_null {
        return Ok(purge_expired_refresh_token_cookie(
            refresh_token_name,
            "You're already logged out. 2",
        ));
    }

    let secret_key_refresh = env::var("SECRET_KEY_REFRESH").unwrap();
    let encoded_refresh_token = JwtDecode::<Claims>(
        &refresh_token_cookie,
        &DecodingKey::from_secret(&secret_key_refresh.as_ref()),
        &Validation::new(Algorithm::HS256),
    );
    // Handle refresh token expired 🚮🍪.
    if let Err(_) = encoded_refresh_token {
        return Ok(purge_expired_refresh_token_cookie(
            refresh_token_name,
            "You're already logged out. 4",
        ));
    } else if get_current_utc_timestamp() > encoded_refresh_token.unwrap().claims.exp {
        return Ok(purge_expired_refresh_token_cookie(
            refresh_token_name,
            "You're already logged out. 3",
        ));
    }

    let stored_user = set_refresh_token_null.unwrap();
    let user = json!({
        "id": stored_user.id,
        "username": stored_user.username,
        "refresh_token": stored_user.refresh_token
    });
    // Final http response and burn a cookie🔥🍪.
    let status_code = StatusCode::OK;
    let response_body = json!({
        "code": status_code.as_u16(),
        "message": "Successfully logged out.",
        "user": user
    });
    let boo_cookie = Cookie::build("refreshToken", "")
        .secure(false)
        .same_site(SameSite::Strict)
        .http_only(true)
        .path("/")
        .expires(CookieTime::OffsetDateTime::now_utc())
        .finish();

    Ok(HttpResponse::build(status_code)
        .cookie(boo_cookie)
        .json(response_body))
}

/// Registers a new user account in the system.
///
/// This endpoint allows the registration of a new user account with a unique username and an optional unique email address.
///
/// # Arguments
///
/// * `app_state`: Shared application state containing the database connection pool.
/// * `json_request`: The JSON payload containing the user registration data (username, password, and optional email).
///
/// # Returns
///
/// Returns a `Result` containing an `HttpResponse` with the created user details or an `AppError` on failure.
///
/// ## Request Body
///
/// The request body must contain a JSON object with the following fields:
/// - `username`: The desired username for the new account.
/// - `password`: The password for the new account.
/// - `email` (optional): The optional email address associated with the new account.
///
/// ## Responses
///
/// - **201 Created:** User account created successfully. Returns details of the newly created user.
///
/// - **409 Conflict:**
///   - `Username already exists:` Indicates that the username is already taken.
///   - `Email is associated with another account:` Indicates that the provided email is associated with another account in the system.
///
/// - **500 Internal Server Error:** Failed to process the request due to an unexpected server error.
///
/// Note: The endpoint checks for the availability of the username and, if provided, the email address before creating the user account.
#[utoipa::path(
    post,
    tag = "Authentication",
    path = "/api/v1/register",
    request_body(content = UserRegisterPayload, description = "", content_type = "application/json"),
    responses(
        (status = 201, description = "User successfully created.", body = User, content_type = "application/json",
            example = json!({
                "code": 201,
                "message": "User 'john' created successfully",
                "user": {
                    "createdAt": "2023-12-25T18:09:30.464795",
                    "email": "johndoe@gmail.com",
                    "id": 1,
                    "password": "$argon2id$v=19$m=19456,t=2,p=1$YRwwW7CxXTKvfMI6WR1Tzw$TlJV/sXyO0+90sOAquDKbdg6NzpYx++srpBS44fQBeo",
                    "refresh_token": null,
                    "role": "user",
                    "updatedAt": "2023-12-25T18:09:30.464795",
                    "username": "john"
                }
            })
        ),
        (status = 409, description = "Conflict - username or email already exists.", body = isize, content_type = "application/json", examples(
            ("Username already exists" = (
                value = json!({
                    "code": 409,
                    "message": "Username is taken."
                })
            )),
            ("Email is associated with another account" = (
                value = json!({
                    "code": 409,
                    "message": "Email 'johndoe@gmail.com' is already associated with another account. Please use another email."
                })
            ))
        )),
        (status = 422, description = "The response indicates a validation error due to invalid data submitted. Details regarding specific validation requirements for `username`, `email`, `password`, and `confirmPassword` fields are provided, helping identify the reasons for failure.", body = isize, content_type = "application/json",
            example = json!({
                "code": 422,
                "details": {
                    "confirmPassword": [
                        "Password do not match. Please ensure both entries are identical."
                    ],
                    "email": [
                        "Invalid email format.",
                        "Email must be a valid email address."
                    ],
                    "password": [
                        "Password must contain at least one uppercase letter, one lowercase letter, one digit, one special characters, is at least 8 characters long, and does not contain spaces.",
                        "Password length must be at least 8 characters long.",
                        "Password must be at least one special character."
                    ],
                    "username": [
                        "Username must consist of alphanumeric characters and be at least 1 characters long.",
                        "Username length must be between 1 to 50 characters long."
                    ]
                },
                "message": "Validation Error"
            })
        ),
        (status = 500, description = "Internal Server Error - Failed to process the request due to an unexpected server error.")
    )
)]
pub async fn auth_register(
    app_state: web::Data<AppState>,
    json_request: web::Json<UserRegisterPayload>,
) -> Result<HttpResponse, AppError> {
    let payload = json_request.into_inner();
    if let Err(err) = payload.validate() {
        return Err(err.into());
    }
    let db_pool = &app_state.get_ref().db_pool;

    // Check username availability.
    let _ = is_username_taken(&payload.username, db_pool).await?;

    // Check email availability.
    if let Some(ref email) = &payload.email {
        let is_email_associated = SqlxQuery("SELECT 1 FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(db_pool)
            .await
            .map_err(|err| {
                AppErrorBuilder::new(
                    StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    String::from("Failed to check if email is associated."),
                    Some(err.to_string()),
                )
                .internal_server_error()
            })?
            .is_some();
        if is_email_associated {
            return Err(AppErrorBuilder::<bool>::new(
                StatusCode::CONFLICT.as_u16(),
                format!(
                    "Email '{}' is already associated with another account. Please use another email.",
                    email
                ),
                None,
            )
            .conflict());
        }
    }

    // Hashing user password.
    let salt_string = SaltString::generate(OsRng);
    let argon2 = Argon2::default();
    let hashed_password = argon2
        .hash_password(&payload.password.as_ref(), &salt_string)
        .map_err(|err| {
            AppErrorBuilder::new(
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                format!("Failed to hash password"),
                Some(err.to_string()),
            )
            .internal_server_error()
        })?
        .to_string();

    let query_result = SqlxQueryAs::<_, User>(
        "INSERT INTO users(username, password, email) VALUES($1,$2,$3) RETURNING *;",
    )
    .bind(&payload.username)
    .bind(hashed_password)
    .bind(&payload.email)
    .fetch_one(db_pool)
    .await?;

    let status_code = StatusCode::CREATED;
    let response_body = json!({
        "code": status_code.as_u16(),
        "message": format!("User '{}' created successfully", &payload.username),
        "user": query_result
    });
    Ok(HttpResponse::build(status_code).json(response_body))
}

/// Handles GET requests to retrieve all users.
///
/// # Arguments
///
/// * `jwt_auth`: The JWT authentication guard.
/// * `app_state`: The shared application state containing the database connection pool.
///
/// # Returns
///
/// A `Result` containing an `HttpResponse` on success, or an `AppError` on failure.
///
/// ## Response
///
/// - 200 OK: Successfully retrieved the list of users.
///   - Returns a JSON object containing details of all users.
/// - 403 Forbidden: Access to this endpoint is not allowed.
///   - Returns a JSON object indicating that the user is not authorized to access this endpoint.
/// - 500 Internal Server Error: Failed to process the request due to an unexpected server error.
///   - Returns a plaintext message indicating the failure to retrieve all users.
///
/// # Security
///
/// This endpoint requires `bearer_auth` security.
#[utoipa::path(
    get,
    tag = "Users Endpoint",
    path = "/api/v1/users",
    responses(
        (status = 200, description = "Successfully all users.", body = User,
            example = json!({
                "code": 200,
                "length": 1,
                "message": "List of users retrieved successfully.",
                "users": [
                    {
                        "createdAt": "2023-12-25T14:13:32.302591",
                        "email": "johndoe@gmail.com",
                        "id": 1,
                        "password": "$argon2id$v=19$m=19456,t=2,p=1$/DbiJMPWhjO39B/SIcVksg$aKYrAF3tvl49QvZmbZNKgf6xPEwz+WIygRcl2Oc5rOY",
                        "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6NSwidXNlcm5hbWUiOiJqb2huIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MDM1MjgwNTYsImV4cCI6MTcwMzUyODExNn0.ugS9DRvtGKj42mwZJ6Mz8T0zjeawM4gj1EunqwPkRxc",
                        "role": "user",
                        "updatedAt": "2023-12-25T18:14:16.903625",
                        "username": "john"
                    },
                    {
                        "createdAt": "2023-12-25T14:09:20.864831",
                        "email": null,
                        "id": 2,
                        "password": "$argon2id$v=19$m=19456,t=2,p=1$pn13Fehy4QzTLs6gbt2rwQ$/0rreylTbp6iXwCYPoRoi6iAYP9nmwcl+ouJy1pSubw",
                        "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6NCwidXNlcm5hbWUiOiJha2l6dWtpIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MDM1MTM0NzYsImV4cCI6MTcwMzUxMzQ3N30.JWmOV0Cs5M-qbaRRxnJe62ei9sMbROMCXoi-ZR1gsoE",
                        "role": "user",
                        "updatedAt": "2023-12-25T14:11:16.814808",
                        "username": "akizuki"
                      }
                ]
            })
        ),
        (status = 403, description = "Forbidden - Access to this endpoint is not allowed.", body = isize, content_type = "application/json", examples(
            ("Not yet authorized" = (
                value = json!({
                    "code": 403,
                    "message": "You're not authorized to access this endpoint."
                })
            ))
        )),
        (status = 500, description = "Internal Failed to process the request due to an unexpected server error.")
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn get_all_users(
    // jwt_auth: JwtAuth,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let db_pool = &app_state.get_ref().db_pool;

    let query_result = SqlxQueryAs::<_, User>("SELECT * FROM users")
        .fetch_all(db_pool)
        .await
        .map_err(|err| {
            AppErrorBuilder::new(
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                String::from("Failed to retrieve all users."),
                Some(err.to_string()),
            )
            .internal_server_error()
        })?;

    let status_code = StatusCode::OK;
    let response_body = json!({
        "code": status_code.as_u16(),
        "message": "List of users retrieved successfully.",
        "length": query_result.len(),
        "users": query_result
    });
    Ok(HttpResponse::Ok().json(response_body))
}

/// Handles GET requests to retrieve a user by their ID.
///
/// # Arguments
///
/// * `app_state`: The shared application state containing the database connection pool.
/// * `pp`: The path parameter containing the `id` of the user to be retrieved.
///
/// # Returns
///
/// A `Result` containing an `HttpResponse` on success, or an `AppError` on failure.
///
/// ## Path Parameters
///
/// * `id`: The ID of the user to retrieve.
///
/// ## Response
///
/// - 200 OK: Successfully retrieved the user.
///   - Returns a JSON object containing details of the user.
/// - 400 Bad Request: Invalid request input.
///   - Returns a plaintext message indicating a parsing error in the request input.
/// - 404 Not Found: Requested user does not exist.
///   - Returns a JSON object indicating that the user with the specified `id` was not found.
/// - 500 Internal Server Error: Failed to process the request due to an unexpected server error.
///   - Returns a plaintext message indicating the failure to retrieve the user.
#[utoipa::path(
    get,
    tag = "Users Endpoint",
    path = "/api/v1/users/{id}",
    params(GetUserPathParams),
    responses(
        (status = 200, description = "Successful user retrieval.", body = User,
            example = json!({
                "code": 200,
                "message": "User retrieved successfully.",
                "user": {
                    "createdAt": "2023-12-25T14:13:32.302591",
                    "email": "johndoe@gmail.com",
                    "id": 1,
                    "password": "$argon2id$v=19$m=19456,t=2,p=1$/DbiJMPWhjO39B/SIcVksg$aKYrAF3tvl49QvZmbZNKgf6xPEwz+WIygRcl2Oc5rOY",
                    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6NSwidXNlcm5hbWUiOiJqb2huIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MDM1MjgwNTYsImV4cCI6MTcwMzUyODExNn0.ugS9DRvtGKj42mwZJ6Mz8T0zjeawM4gj1EunqwPkRxc",
                    "role": "user",
                    "updatedAt": "2023-12-25T18:14:16.903625",
                    "username": "john"
                }
            })
        ),
        (status = 400, description = "Invalid request input.", body = String, content_type = "text/plain",
            example = json!(r#"can not parse "satu" to a i32"#)
        ),
        (status = 404, description = "User not found.", body = isize, content_type = "application/json",
            example = json!({
                "code": 404,
                "message": "User with id: '39' not found"
            })
        ),
        (status = 500, description = "Internal Failed to process the request due to an unexpected server error.")
    )
)]
pub async fn get_user(
    app_state: web::Data<AppState>,
    pp: web::Path<GetUserPathParams>,
) -> Result<HttpResponse, AppError> {
    let db_pool = &app_state.get_ref().db_pool;
    let user_id = pp.into_inner().id;

    let query_result = SqlxQueryAs::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(db_pool)
        .await
        .map_err(|err| {
            AppErrorBuilder::new(
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                format!("Failed to retrieve user with id: '{}'", user_id),
                Some(err.to_string()),
            )
            .internal_server_error()
        })?;

    if let Some(result) = query_result {
        let status_code = StatusCode::OK;
        let response_body = json!({
            "code": status_code.as_u16(),
            "message": "User retrieved successfully.",
            "user": result
        });
        Ok(HttpResponse::build(status_code).json(response_body))
    } else {
        Err(AppErrorBuilder::<bool>::new(
            StatusCode::NOT_FOUND.as_u16(),
            format!("User with id: '{}' not found", user_id),
            None,
        )
        .not_found())
    }
}

/// Handles PUT requests to update user details based on the provided ID.
///
/// # Arguments
///
/// * `app_state`: The shared application state containing the database connection pool.
/// * `pp`: The path parameter containing the `id` of the user to be updated.
/// * `json_request`: The JSON payload containing the updated user details.
///
/// # Returns
///
/// A `Result` containing an `HttpResponse` on success, or an `AppError` on failure.
///
/// ## Path Parameters
///
/// * `id`: The ID of the user to update.
///
/// ## Request Body
///
/// Expects a JSON payload (`UserUpdatePayload`) containing the updated user details.
///
/// ## Response
///
/// - 200 OK: User details updated successfully.
///   - Returns a JSON object containing the updated user details.
/// - 404 Not Found: Requested user does not exist.
///   - Returns a JSON object indicating that the user with the specified `id` was not found.
/// - 409 Conflict: Username or Email is already associated with another account.
///   - Returns a JSON object indicating a conflict due to a username or email already being taken.
/// - 500 Internal Server Error: Failed to process the request due to an unexpected server error.
///   - Returns a plaintext message indicating the failure to update the user.
#[utoipa::path(
    put,
    tag = "Users Endpoint",
    path = "/api/v1/users/{id}",
    params(UpdateUserPathParams),
    request_body(content = UserUpdatePayload, description = "Payload for updating user information.", content_type = "application/json"),
    responses(
        (status = 200, description = "OK - User details updated successfully.", body = User,
            example = json!({
                "code": 200,
                "message": "User updated successfully.",
                "user": {
                    "createdAt": "2023-12-25T12:55:33.176614",
                    "email": "yamadataro@gmail`.com",
                    "id": 1,
                    "password": "$argon2id$v=19$m=19456,t=2,p=1$q2AHmfsuZPbaBcNrgZdZdQ$+FSMzwyGg2sghBwBh0MSKhkvD4hn1f8aoYQnzrvENFs",
                    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJzZXRzdW5hIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MDM1MDkwNTMsImV4cCI6MTcwMzUwOTA1NH0.NRLFQppvXIBgCOh2VF38BichWGOgE0iSj4By-vPoJ5o",
                    "role": "user",
                    "updatedAt": "2023-12-26T02:40:18.383154",
                    "username": "yamada"
                }
            })
        ),
        (status = 404, description = "Not Found - User not found with the specified ID.", body = isize, content_type = "application/json",
            example = json!({
                "code": 500,
                "message": "User with id: '10' not found."
            })
        ),
        (status = 409, description = "Conflict - Resource conflict occurred.", body = isize, content_type = "application/json", examples(
            ("Username is taken" = (
                value = json!({
                    "code": 409,
                    "message": "Username 'john' is taken. Please choose another username."
                })
            )),
            ("Email is associated with another account" = (
                value = json!({
                    "code": 409,
                    "message": "Email 'johndoe@gmail.com' is already associated to another account. Please use another email."
                })
            ))
        )),
        (status = 500, description = "Internal Server Error - Failed to process the request due to an unexpected server error.")
    )
)]
pub async fn update_user(
    app_state: web::Data<AppState>,
    pp: web::Path<UpdateUserPathParams>,
    json_request: web::Json<UserUpdatePayload>,
) -> Result<HttpResponse, AppError> {
    let user_id = pp.into_inner().id;

    let payload = json_request.into_inner();
    // Validate user input entity.
    if let Err(err) = payload.validate() {
        return Err(err.into());
    }

    let db_pool = &app_state.get_ref().db_pool;

    // Check is user update exists.
    let stored_user = SqlxQueryAs::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(db_pool)
        .await
        .map_err(|err| {
            AppErrorBuilder::new(
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                format!("Failed to retrieve user with id: '{}'.", user_id),
                Some(err.to_string()),
            )
            .internal_server_error()
        })?
        .ok_or_else(|| {
            AppErrorBuilder::<bool>::new(
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                format!("User with id: '{}' not found.", user_id),
                None,
            )
            .not_found()
        })?;

    // Check username availability.
    if let Some(ref new_username) = payload.username.clone() {
        let is_username_taken = SqlxQuery("SELECT 1 FROM users WHERE username = $1")
            .bind(new_username)
            .fetch_one(db_pool)
            .await
            .is_ok();
        if is_username_taken && new_username != &stored_user.username {
            return Err(AppErrorBuilder::<bool>::new(
                StatusCode::CONFLICT.as_u16(),
                format!(
                    "Username '{}' is taken. Please choose another username.",
                    new_username
                ),
                None,
            )
            .conflict());
        }
    }
    // Check email availability.
    if let Some(ref new_email) = payload.email.clone() {
        let is_email_associated = SqlxQuery("SELECT 1 FROM users WHERE email = $1")
            .bind(new_email)
            .fetch_one(db_pool)
            .await
            .is_ok();
        if is_email_associated && new_email != &stored_user.email.clone().unwrap_or_default() {
            /* <- potential buggy */
            return Err(AppErrorBuilder::<bool>::new(
                StatusCode::CONFLICT.as_u16(),
                format!(
                    "Email '{}' is already associated to another account. Please use another email.",
                    new_email
                ),
                None,
            )
           .conflict());
        }
    }
    // Hashing new provided password or return old / stored password.
    let password = if let Some(ref password) = payload.password {
        let salt_string = SaltString::generate(OsRng);
        let argon2 = Argon2::default();
        let hashed_new_password = argon2
            .hash_password(password.as_ref(), &salt_string)
            .map_err(|err| {
                AppErrorBuilder::new(
                    StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    format!("Failed to hash password."),
                    Some(err.to_string()),
                )
                .internal_server_error()
            })?
            .to_string();
        hashed_new_password
    } else {
        stored_user.password
    };
    let username = payload.username.unwrap_or(stored_user.username);
    // let email = payload
    //     .email
    //     .unwrap_or(stored_user.email.unwrap_or_default()); /* <- potential buggy */
    let email = match payload.email.as_deref() {
        Some("null") => None,
        Some(email) => Some(email),
        None => stored_user.email.as_deref().or(Some("null")),
    };

    let sql_query = if email == Some("null") {
        SqlxQueryAs::<_, User>(
            "UPDATE users SET username = $1, password = $2 WHERE id = $3 RETURNING *;",
        )
        .bind(username)
        .bind(password)
        .bind(user_id)
    } else {
        SqlxQueryAs::<_, User>(
            "UPDATE users SET username = $1, password = $2, email = $3 WHERE id = $4 RETURNING *;",
        )
        .bind(username)
        .bind(password)
        .bind(email)
        .bind(user_id)
    };

    let query_result = sql_query.fetch_optional(db_pool).await.map_err(|err| {
        AppErrorBuilder::new(
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            format!("Failed to update user with id: '{}'", user_id),
            Some(err.to_string()),
        )
        .internal_server_error()
    })?;

    if let Some(result) = query_result {
        let status_code = StatusCode::OK;
        let response_body = json!({
            "code": status_code.as_u16(),
            "message": "User updated successfully.",
            "user": result
        });
        Ok(HttpResponse::build(status_code).json(response_body))
    } else {
        Err(AppErrorBuilder::<bool>::new(
            StatusCode::NOT_FOUND.as_u16(),
            format!("User with id: '{}' not found.", user_id),
            None,
        )
        .not_found())
    }
}

/// Deletes a user by their ID.
///
/// # Endpoint
/// DELETE `/api/v1/users/{id}`
///
/// # Parameters
/// - `id`: The unique identifier of the user to be deleted.
///
/// # Responses
///
/// - 200 OK: User deleted successfully.
/// - 403 Forbidden: Access to this endpoint is not allowed.
/// - 404 Not Found: User not found.
/// - 500 Internal Server Error: Failed to process the request due to an unexpected server error.
///
/// # Security
/// This endpoint requires a bearer token for authorization.
#[utoipa::path(
    delete,
    tag = "Users Endpoint",
    path = "/api/v1/users/{id}",
    params(DeleteUserPathParams),
    responses(
        (status = 200, description = "OK - User deleted successfully.", body = User,
            example = json!({
                "code": 200,
                "message": "User deleted successfully",
                "user": {
                    "createdAt": "2023-12-25T12:55:33.176614",
                    "email": "yamadataro@gmail.com",
                    "id": 1,
                    "password": "$argon2id$v=19$m=19456,t=2,p=1$q2AHmfsuZPbaBcNrgZdZdQ$+FSMzwyGg2sghBwBh0MSKhkvD4hn1f8aoYQnzrvENFs",
                    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJzZXRzdW5hIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MDM1MDkwNTMsImV4cCI6MTcwMzUwOTA1NH0.NRLFQppvXIBgCOh2VF38BichWGOgE0iSj4By-vPoJ5o",
                    "role": "user",
                    "updatedAt": "2023-12-26T02:40:18.383154",
                    "username": "yamada"
                }
            })
        ),
        (status = 403, description = "Forbidden - Access to this endpoint is not allowed.", body = isize, content_type = "application/json", examples(
            ("Not yet authorized" = (
                value = json!({
                    "code": 403,
                    "message": "You're not authorized to access this endpoint."
                })
            )),
            ("Not allowed" = (
                value = json!({
                    "code": 403,
                    "message": "You're not allowed to access this."
                })
            ))
        )),
        (status = 404, description = "User not found.", body = isize, content_type = "application/json",
            example = json!({
                "code": 404,
                "message": "User with id: '39' not found"
            })
        ),
        (status = 500, description = "Internal Server Error - Failed to process the request due to an unexpected server error.")
    ),
    security(
        ("bearer_auth"= [])
    )
)]
pub async fn delete_user(
    // jwt_auth: JwtAuth,
    app_state: web::Data<AppState>,
    pp: web::Path<DeleteUserPathParams>,
) -> Result<HttpResponse, AppError> {
    let user_id = pp.into_inner().id;
    // let auth_role = jwt_auth.role;
    // if auth_role != "admin" {
    //     return Err(AppErrorBuilder::<bool>::new(
    //         StatusCode::FORBIDDEN.as_u16(),
    //         String::from("You're not allowed to access this."),
    //         None,
    //     )
    //     .forbidden());
    // }
    let db_pool = &app_state.get_ref().db_pool;

    let query_result = SqlxQueryAs::<_, User>("DELETE FROM users WHERE id = $1 RETURNING *;")
        .bind(user_id)
        .fetch_optional(db_pool)
        .await
        .map_err(|err| {
            AppErrorBuilder::new(
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                format!("Failed to delete user with id: '{}'", user_id),
                Some(err.to_string()),
            )
            .internal_server_error()
        })?;

    if let Some(result) = query_result {
        let status_code = StatusCode::OK;
        let response_body = json!({
            "code": status_code.as_u16(),
            "message": "User deleted successfully",
            "user": result
        });
        Ok(HttpResponse::build(status_code).json(response_body))
    } else {
        Err(AppErrorBuilder::<bool>::new(
            StatusCode::NOT_FOUND.as_u16(),
            format!("User with id: '{}' not found", user_id),
            None,
        )
        .not_found())
    }
}
