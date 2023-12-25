use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;

#[derive(FromRow, Serialize, Clone, ToSchema)]
pub struct User {
    #[schema(example = "1")]
    pub id: i32,
    #[schema(example = "john", required = true)]
    pub username: String,
    #[schema(example = "$argon2id$v=19$m=19456,t=2,p=1$/DbiJMPWhjO39B/SIcVksg$aKYrAF3tvl49QvZmbZNKgf6xPEwz+WIygRcl2Oc5rOY", required = true)]
    pub password: String,
    #[schema(example = "johndoe@email.com", required = false)]
    pub email: Option<String>,
    #[schema(example = "user")]
    pub role: String,
    #[schema(example = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6NCwidXNlcm5hbWUiOiJha2l6dWtpIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MDM1MTM0NzYsImV4cCI6MTcwMzUxMzQ3N30.JWmOV0Cs5M-qbaRRxnJe62ei9sMbROMCXoi-ZR1gsoE", required = false)]
    pub refresh_token: Option<String>,
    #[schema(example = "2023-12-25 14:13:32.302591")]
    #[serde(rename = "createdAt")]
    pub created_at: NaiveDateTime,
    #[schema(example = "2023-12-25 17:35:54.246533")]
    #[serde(rename = "updatedAt")]
    pub updated_at: NaiveDateTime,
}

#[derive(Serialize, FromRow, ToSchema)]
pub struct UserClaims {
    #[schema(example = "1")]
    pub id: i32,
    #[schema(example = "john")]
    pub username: String,
    #[schema(example = "user")]
    pub role: String
}

#[derive(Deserialize, ToSchema)]
pub struct UserLoginPayload {
    #[schema(example = "john", required = true)]
    pub username: String,
    #[schema(example = "Johndoe123@", required = true)]
    pub password: String
}
#[derive(Deserialize, ToSchema)]
pub struct UserRegisterPayload {
    #[schema(example = "john", required = true)]
    pub username: String,
    #[schema(example = "Johndoe123@", required = true)]
    pub password: String,
    #[schema(example = "johndoe@email.com", required = false)]
    pub email: Option<String>,
}
#[derive(Deserialize)]
pub struct UserUpdatePayload {
    pub username: Option<String>,
    pub password: Option<String>,
    pub email: Option<String>
}
