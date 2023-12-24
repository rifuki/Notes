use actix_web::{get, HttpResponse};
use serde_json::json;

#[get("/ping")]
pub async fn ping_service() -> HttpResponse {
    let response_body = json!({
        "message": "pong"
    });

    HttpResponse::Ok().json(response_body)
}
