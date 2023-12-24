use serde::Deserialize;

#[derive(Deserialize)]
pub struct GetUserPathParams {
    pub id: i32
}

#[derive(Deserialize)]
pub struct UpdateUserPathParams {
    pub id: i32
}

#[derive(Deserialize)]
pub struct DeleteUserPathParams {
    pub id: i32
}