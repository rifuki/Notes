use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPool;

pub type DbPool = PgPool;

#[derive(Clone)]
pub struct AppState {
    pub db_pool: DbPool,
}

#[derive(Serialize, Clone, Deserialize)]
pub struct Claims {
    pub id: i32,
    pub username: String,
    pub role: String,
    pub iat: i64,
    pub exp: i64,
}

pub enum UserRole {
    User,
    Admin,
}

impl UserRole {
    pub fn to_string(&self) -> String {
        match *self {
            Self::Admin => String::from("admin"),
            Self::User => String::from("user"),
        }
    }
}
