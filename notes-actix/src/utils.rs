use bb8::Pool as Bb8Pool;
use bb8_redis::RedisConnectionManager;
use chrono::{Duration as ChronoDuration, Utc};
use once_cell::sync::Lazy;
use sqlx::postgres::PgPoolOptions;
use std::{env, time::Duration};

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

pub const CHRONO_ACCESS_DURATION: Lazy<ChronoDuration> = Lazy::new(|| {
    let access_token_duration = env::var("TOKEN_DURATION_ACCESS")
        .unwrap()
        .parse::<i64>()
        .unwrap();
    ChronoDuration::seconds(access_token_duration)
});

pub const CHRONO_REFRESH_DURATION: Lazy<ChronoDuration> = Lazy::new(|| {
    let refresh_token_duration = env::var("TOKEN_DURATION_REFRESH")
        .unwrap()
        .parse::<i64>()
        .unwrap();
    ChronoDuration::seconds(refresh_token_duration)
});
