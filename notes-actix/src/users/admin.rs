use actix_web::{http::StatusCode, web, HttpResponse};
use serde_json::json;
use sqlx::query_as as SqlxQueryAs;
use validator::Validate;

use crate::{
    errors::{AppError, AppErrorBuilder},
    types::AppState,
    users::{
        helpers::{hashing_password, is_username_taken},
        models::{AdminBuilder, User},
    },
};

/// Registers a new admin account in the system.
///
/// This endpoint allows the registration of a new admin account with a unique username and an optional unique email address.
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
    path = "/api/v1/admin/register",
    request_body(content = AdminBuilder, description = "", content_type = "application/json"),
    responses(
        (status = 201, description = "User successfully created.", body = User, content_type = "application/json",
            example = json!({
                "admin": {
                    "createdAt": "2023-12-27T12:03:26.666995",
                    "email": null,
                    "id": 1,
                    "password": "$argon2id$v=19$m=19456,t=2,p=1$up+yHtkp+0rEhVjDSe/DpA$mq3eSNrWG2ivfSA2YbvxsYVjb/HCXoIKIMCTf0IgqIk",
                    "refresh_token": null,
                    "role": "admin",
                    "updatedAt": "2023-12-27T12:03:26.666995",
                    "username": "john"
                },
                "code": 200,
                "message": "User 'john' created successfully"
            })
        ),
        (status = 403, description = "Forbidden - Access to this endpoint is not allowed.", body = isize, content_type = "application/json",
        example = json!({
            "code": 403,
            "message": "You're not allowed to access this endpoint."
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

pub async fn register_admin(
    app_state: web::Data<AppState>,
    request_json: web::Json<AdminBuilder>,
) -> Result<HttpResponse, AppError> {
    let payload = request_json.into_inner();
    if let Err(err) = payload.validate() {
        return Err(err.into());
    }

    // Super secret key.
    if payload.secret_key != "super_secret_key~" {
        return Err(AppErrorBuilder::<bool>::new(
            StatusCode::FORBIDDEN.as_u16(),
            String::from("You're not allowed to access this endpoint."),
            None,
        )
        .forbidden());
    }

    let db_pool = &app_state.get_ref().db_pool;

    // Checking username availability.
    let _ = is_username_taken(&payload.username, db_pool).await?;

    // Hashing admin password.
    let hashed_password = hashing_password(&payload.password)?;

    // Stored new admin data.
    let registered_admin = SqlxQueryAs::<_, User>(
        "INSERT INTO users (username, password, role) VALUES ($1, $2, 'admin') RETURNING *;",
    )
    .bind(&payload.username)
    .bind(&hashed_password)
    .fetch_optional(db_pool)
    .await
    .map_err(|err| {
        log::error!("Failed to insert admin data: {}", err);
        AppErrorBuilder::new(
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            String::from("Failed to register admin."),
            Some(err.to_string()),
        )
        .internal_server_error()
    })?
    .ok_or_else(|| {
        AppErrorBuilder::<bool>::new(
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            String::from("Failed to register admin."),
            None,
        )
        .internal_server_error()
    })?;

    // Constructs the response body to be sent back after a successful admin registered. 🔥
    let status_code = StatusCode::OK;
    let response_body = json!({
        "code": status_code.as_u16(),
        "message": format!("User '{}' created successfully", &payload.username),
        "admin": registered_admin
    });
    Ok(HttpResponse::Ok().json(response_body))
}
