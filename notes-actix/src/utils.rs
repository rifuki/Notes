use bb8::Pool as Bb8Pool;
use bb8_redis::RedisConnectionManager;
use chrono::Utc;
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;

use crate::types::{DbPool, RedisPool};

pub async fn establish_database_pool(db_url: &str) -> DbPool {
    PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(15))
        .connect(db_url)
        .await
        .unwrap_or_else(|err| panic!("Failed to establish connection. {}", err))
}

pub async fn initialize_redis_pool(redis_url: &str) -> RedisPool {
    let manager = RedisConnectionManager::new(redis_url)
        .unwrap_or_else(|err| panic!("Failed to initialize connection manager. {}", err));
    Bb8Pool::builder()
        .build(manager)
        .await
        .unwrap_or_else(|err| panic!("Failed to initialize pool. {}", err))
}

pub fn get_current_utc_timestamp() -> i64 {
    Utc::now().naive_utc().timestamp()
}
