use bb8::Pool as Bb8Pool;
use bb8_redis::RedisConnectionManager;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPool;

pub type DbPool = PgPool;
pub type RedisPool = Bb8Pool<RedisConnectionManager>;

#[derive(Clone, Debug)]
pub struct AppState {
    pub db_pool: DbPool,
    pub redis_pool: RedisPool,
}

#[derive(Serialize, Clone, Deserialize)]
pub struct Claims {
    pub aud: i32,
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
    pub jti: String,
    pub role: String,
    pub email: Option<String>,
    pub username: String,
}
pub enum ClaimsToken {
    Access,
    Refresh,
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

pub enum RedisKey {
    BlacklistAccessToken,
    BlacklistRefreshToken,
}
impl RedisKey {
    pub fn to_string(&self) -> String {
        match *self {
            Self::BlacklistAccessToken => String::from("x!act"),
            Self::BlacklistRefreshToken => String::from("x!rft"),
        }
    }
}
