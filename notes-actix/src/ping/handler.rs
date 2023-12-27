use actix_web::{
    cookie::{time::Duration, Cookie, SameSite},
    get,
    http::header,
    HttpResponse,
};
use chrono::Utc;
use serde_json::json;

/// Health Check - Ping Service
///
/// This endpoint is used to check the health of the service and its availability.
///
/// ### Responses
///
/// - **200 OK**
///   - *Description*: Health check endpoint to verify service availability.
///
/// ### Security Headers
///
/// This endpoint includes the following security-related headers in the response:
/// - `Content-Security-Policy`: Set your policy here.
/// - `Strict-Transport-Security`: max-age=31536000
/// - `X-Content-Type-Options`: nosniff
///
/// ### Additional Headers
///
/// Apart from security headers, this endpoint includes a custom header:
/// - `PING`: "yay" repeated 10 times
///
/// ## Usage
///
/// Make a GET request to the `/ping` endpoint and examine the response for service availability.
///
/// ```rust
/// // Example request to the ping service endpoint.
/// let response = ping_service().await;
/// assert_eq!(response.status(), 200);
/// // Further checks on the response content if needed.
/// ```
#[utoipa::path(
    get,
    tag = "HealthCheck",
    path = "/ping",
    responses(
        (status = 200, description = "OK - Health check endpoint to verify service availability.", body = isize, content_type = "application/json",
            example = json!({
                "message": "ping"
            }),
            headers(
                ("Accept-Language"),
                ("Content-Length" = i32),
                ("Content-Security-Policy"),
                ("Content-Type"),
                ("Ping"),
                ("Strict-Transport-Security"),
                ("X-Content-Type-Options")
            )
        )
    ),
    
)]
#[get("/ping")]
pub async fn ping_service() -> HttpResponse {
    let response_body = json!({
        "message": "pong"
    });

    let yay_cookie = Cookie::build("ping", "yay ".repeat(100))
        .secure(false)
        .same_site(SameSite::Strict)
        .http_only(true)
        .path("/")
        .max_age(Duration::MINUTE)
        .finish();

    HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header((header::CONTENT_SECURITY_POLICY, "your_policy_here"))
        .insert_header((header::STRICT_TRANSPORT_SECURITY, "max-age=31536000"))
        .insert_header(("PING", "yay ".repeat(10)))
        .insert_header((header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .insert_header((header::ACCEPT_LANGUAGE, "en-US"))
        .cookie(yay_cookie)
        .json(response_body)

}

/// Handler to retrieve the server time.
///
/// Retrieves the current server time in UTC format.
///
/// # Returns
///
/// Returns a JSON response containing the current server time.
#[utoipa::path(
    get,
    tag = "HealthCheck",
    path = "/time",
    responses(
        (status = 200, description = "OK - Server time.", body = String, content_type = "application/json",
            example = json!({
                "server_time": "2023-12-27 12:55:25.791472 UTC"
            })
        )
    )
)]
#[get("/time")]
pub async fn server_time() -> HttpResponse {
    HttpResponse::Ok()
      .insert_header((header::CONTENT_TYPE, "application/json"))
      .json(json!({
            "server_time": Utc::now().to_string()
        }))
}
