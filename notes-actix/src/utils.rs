use chrono::Utc;
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;

use crate::types::DbPool;

pub fn establish_connection(db_url: &str) -> DbPool {
    PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(15))
        .min_connections(5)
        .max_connections(150)
        .idle_timeout(Duration::from_secs(15))
        .connect_lazy(db_url)
        .unwrap_or_else(|err| panic!("Failed to establish connection. {}", err))
}

pub fn get_current_utc_timestamp() -> i64 {
    Utc::now().naive_utc().timestamp()
}
