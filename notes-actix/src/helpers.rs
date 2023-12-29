use actix_web::http::StatusCode;
use bb8::PooledConnection;
use bb8_redis::{redis::AsyncCommands, RedisConnectionManager};

use crate::{
    errors::{AppError, AppErrorBuilder},
    types::RedisKey,
};

pub async fn handle_blacklist_token(
    auth_id: i32,
    mut redis_pool: PooledConnection<'_, RedisConnectionManager>,
) -> Result<(), AppError> {
    let key_redis = format!("{}-{}", RedisKey::BlacklistToken.to_string(), auth_id);
    let is_token_blacklisted = redis_pool.get::<_, String>(key_redis).await;
    if is_token_blacklisted.is_ok() {
        return Err(AppErrorBuilder::<bool>::new(
            StatusCode::UNAUTHORIZED.as_u16(),
            String::from("You're not authorized to access this endpoint."),
            None,
        )
        .unauthorized());
    }

    Ok(())
}
