use actix_web::{HttpResponse, web, http::StatusCode};
use serde_json::json;
use sqlx::query_as as SqlxQueryAs;

use crate::{types::AppState, errors::AppError, users::models::{UserBuilder, User, UserRole}};



pub async fn auth_login(
    // app_state: web::Data<AppState>
) -> Result<HttpResponse, AppError> {
    Ok(HttpResponse::Ok().json(json!({
        "users": "auth_login"
    })))
}

pub async fn auth_register(
    app_state: web::Data<AppState>,
    json_request: web::Json<UserBuilder>
) -> Result<HttpResponse, AppError> {
    let payload = json_request.into_inner();
    let db_pool = &app_state.get_ref().db_pool;
    
    let email = match &payload.email {
        Some(email) => email,
        None => "NULL"
    };
    let query_result = SqlxQueryAs!(User, r#"INSERT INTO users (username, password, email, role) VALUES ($1, $2, $3, 'user') RETURNING id, username, password, email, role AS "role: _", created_at, updated_at"#, &payload.username, &payload.password, email) 
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

pub async fn get_all_users(
    app_state: web::Data<AppState>
) -> Result<HttpResponse, AppError> {
    let db_pool = &app_state.get_ref().db_pool;

    let query_result = SqlxQueryAs!(User, r#"SELECT id, username, password, email, role as "role: UserRole", created_at, updated_at FROM users"#)
        .fetch_all(db_pool)
        .await?;

    let status_code = StatusCode::OK;
    let response_body = json!({
        "code": status_code.as_u16(),
        "message": "List of users retrieved successfully",
        "users": query_result
    });
    Ok(HttpResponse::Ok().json(response_body)) 
}

pub async fn get_user(
    // app_state: web::Data<AppState>
) -> Result<HttpResponse, AppError> {
    Ok(HttpResponse::Ok().json(json!({
        "users": "get_user"
    })))
}

pub async fn update_user(
    // app_state: web::Data<AppState>
) -> Result<HttpResponse, AppError> {
    Ok(HttpResponse::Ok().json(json!({
        "users": "update_user"
    })))
}

pub async fn delete_user(
    // app_state: web::Data<AppState>
) -> Result<HttpResponse, AppError> {
    Ok(HttpResponse::Ok().json(json!({
        "users": "delete_user"
    })))
}