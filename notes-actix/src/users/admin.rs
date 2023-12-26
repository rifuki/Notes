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

pub async fn register_admin(
    app_state: web::Data<AppState>,
    request_json: web::Json<AdminBuilder>,
) -> Result<HttpResponse, AppError> {
    let payload = request_json.into_inner();
    if let Err(err) = payload.validate() {
        return Err(err.into());
    }

    // Super secret magic.
    if payload.secret_key != "super_secret_key~" {
        return Err(AppErrorBuilder::<bool>::new(
            StatusCode::FORBIDDEN.as_u16(),
            String::from("You're not allowed to access this."),
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
    let query_result = SqlxQueryAs::<_, User>(
        "INSERT INTO users (username, password, role) VALUES ($1, $2, 'admin') RETURNING *;",
    )
    .bind(&payload.username)
    .bind(&hashed_password)
    .fetch_optional(db_pool)
    .await
    .map_err(|err| {
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

    // Final response.
    let status_code = StatusCode::OK;
    let response_body = json!({
        "code": status_code.as_u16(),
        "message": format!("User '{}' created successfully", &payload.username),
        "admin": query_result
    });
    Ok(HttpResponse::Ok().json(response_body))
}
