use sqlx::postgres::PgPool;

pub type DbPool = PgPool;

#[derive(Clone)]
pub struct AppState {
    pub db_pool: DbPool
}