use serde::{Serialize, Deserialize};
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
