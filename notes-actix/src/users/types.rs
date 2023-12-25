use serde::Deserialize;
use utoipa::IntoParams;

#[derive(Deserialize, IntoParams)]
pub struct GetUserPathParams {
    pub id: i32
}

#[derive(Deserialize, IntoParams)]
pub struct UpdateUserPathParams {
    pub id: i32
}

#[derive(Deserialize, IntoParams)]
pub struct DeleteUserPathParams {
    pub id: i32
}