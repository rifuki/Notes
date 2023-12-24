use actix_web::{http::StatusCode, web, HttpResponse};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use serde_json::json;
use sqlx::{query as SqlxQuery, query_as as SqlxQueryAs};

use crate::{
    errors::{AppError, AppErrorBuilder},
    types::AppState,
    users::{
        models::{User, UserBuilder, UserLogin, UserNoPassword, UserUpdate},
        types::{DeleteUserPathParams, GetUserPathParams, UpdateUserPathParams},
    },
};

pub async fn auth_login(
    app_state: web::Data<AppState>,
    request_body: web::Json<UserLogin>,
) -> Result<HttpResponse, AppError> {
    let payload = request_body.into_inner();
    let db_pool = &app_state.get_ref().db_pool;

    let stored_user = SqlxQueryAs::<_, User>("SELECT * FROM users WHERE username = $1")
        .bind(&payload.username)
        .fetch_one(db_pool)
        .await
        .map_err(|_| {
            AppErrorBuilder::<bool>::new(
                StatusCode::UNAUTHORIZED.as_u16(),
                format!("Invalid username or password."),
                None,
            )
            .unauthorized()
        })?;

    let parsed_stored_password = PasswordHash::new(&stored_user.password).unwrap();
    let argon2 = Argon2::default();
    let _verify_password = argon2
        .verify_password(&payload.password.as_ref(), &parsed_stored_password)
        .map_err(|_| {
            AppErrorBuilder::<bool>::new(
                StatusCode::UNAUTHORIZED.as_u16(),
                format!("Invalid username or password."),
                None,
            )
            .unauthorized()
        })?;

    let status_code = StatusCode::OK;
    let response_body = json!({
        "code": status_code.as_u16(),
        "message": "Successfully logged in",
        "user": stored_user
    });
    Ok(HttpResponse::build(status_code).json(response_body))
}

pub async fn auth_register(
    app_state: web::Data<AppState>,
    json_request: web::Json<UserBuilder>,
) -> Result<HttpResponse, AppError> {
    let payload = json_request.into_inner();
    let db_pool = &app_state.get_ref().db_pool;

    // Check username availability.
    let is_username_taken = SqlxQuery("SELECT 1 FROM users WHERE username = $1")
        .bind(&payload.username)
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
        .conflict());
    }
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

    let query_result = SqlxQueryAs::<_, UserNoPassword>(
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
        "message": format!("User {} created successfully", &payload.username),
        "user": query_result
    });
    Ok(HttpResponse::build(status_code).json(response_body))
}

pub async fn get_all_users(app_state: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    let db_pool = &app_state.get_ref().db_pool;

    let query_result = SqlxQueryAs::<_, User>("SELECT * FROM users")
        .fetch_all(db_pool)
        .await?;

    let status_code = StatusCode::OK;
    let response_body = json!({
        "code": status_code.as_u16(),
        "message": "List of users retrieved successfully.",
        "length": query_result.len(),
        "users": query_result
    });
    Ok(HttpResponse::Ok().json(response_body))
}

pub async fn get_user(
    app_state: web::Data<AppState>,
    pp: web::Path<GetUserPathParams>,
) -> Result<HttpResponse, AppError> {
    let db_pool = &app_state.get_ref().db_pool;
    let user_id = pp.into_inner().id;

    let query_result = SqlxQueryAs::<_, UserNoPassword>("SELECT * FROM users WHERE id = $1")
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

pub async fn update_user(
    app_state: web::Data<AppState>,
    pp: web::Path<UpdateUserPathParams>,
    json_request: web::Json<UserUpdate>,
) -> Result<HttpResponse, AppError> {
    let payload = json_request.into_inner();
    let user_id = pp.into_inner().id;
    let db_pool = &app_state.get_ref().db_pool;

    // Check is user update exists.
    let stored_user = SqlxQueryAs::<_, User>("SELECT * FROM users WHERE id = $1")
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
        })?
        .ok_or_else(|| {
            AppErrorBuilder::<bool>::new(
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                format!("User with id: '{}' not found", user_id),
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
                    format!("Failed to hash password"),
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
    let email = payload
        .email
        .unwrap_or(stored_user.email.unwrap_or_default());

    let query_result = SqlxQueryAs::<_, User>(
        "UPDATE users SET username = $1, password = $2, email = $3 WHERE id = $4 RETURNING *",
    )
    .bind(username)
    .bind(password)
    .bind(email)
    .bind(user_id)
    .fetch_optional(db_pool)
    .await
    .map_err(|err| {
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
            format!("User with id: '{}' not found", user_id),
            None,
        )
        .not_found())
    }
}

pub async fn delete_user(
    app_state: web::Data<AppState>,
    pp: web::Path<DeleteUserPathParams>,
) -> Result<HttpResponse, AppError> {
    let db_pool = &app_state.get_ref().db_pool;
    let user_id = pp.into_inner().id;

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
