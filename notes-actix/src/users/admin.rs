use actix_web::{http::StatusCode, web, HttpResponse};
use sqlx::{query as SqlxQuery, query_as as SqlxQueryAs};

use crate::{
    errors::{AppError, AppErrorBuilder},
    types::AppState,
    users::models::User,
};

pub struct AdminBuilder {
    username: String,
    password: String,
    secret_word: String,
}

pub async fn register_admin(
    app_state: web::Data<AppState>,
    request_json: web::Json<AdminBuilder>,
) -> Result<HttpResponse, AppError> {
    let payload = request_json.into_inner();

    if payload.secret_word != "super_secret" {
        return Err(AppErrorBuilder::<bool>::new(
            StatusCode::FORBIDDEN.as_u16(),
            String::from("You're not allowed to access this."),
            None,
        )
        .forbidden());
    }

    let db_pool = &app_state.get_ref().db_pool;

    Ok(HttpResponse::Ok().finish())
}
