use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;
use validator::Validate;

#[derive(FromRow, Serialize, ToSchema)]
pub struct Note {
    #[schema(example = "1")]
    pub id: i32,
    #[schema(example = "My Title")]
    pub title: String,
    #[schema(example = "This is my body note.")]
    pub body: String,
    #[serde(rename = "userId")]
    #[schema(example = "1")]
    pub user_id: i32,
    #[schema(example = "2023-12-23T23:13:05.151333")]
    #[serde(rename = "createdAt")]
    pub created_at: NaiveDateTime,
    #[schema(example = "2023-12-23T23:15:05:342034")]
    #[serde(rename = "updatedAt")]
    pub updated_at: NaiveDateTime,
}

#[derive(FromRow, Serialize, ToSchema)]
pub struct NoteJoinUser {
    #[schema(example = "1")]
    pub id: i32,
    #[schema(example = "john")]
    pub username: String,
    #[schema(example = "My Title")]
    pub title: String,
    #[schema(example = "This is my body note.")]
    pub body: String,
    #[serde(rename = "userId")]
    #[schema(example = "1")]
    pub user_id: i32,
    #[schema(example = "2023-12-23T23:13:05.151333")]
    #[serde(rename = "createdAt")]
    pub created_at: NaiveDateTime,
    #[schema(example = "2023-12-23T23:15:05:342034")]
    #[serde(rename = "updatedAt")]
    pub updated_at: NaiveDateTime,
}

#[derive(Deserialize, Validate, ToSchema, Serialize)]
pub struct NoteBuilder {
    #[validate(length(
        min = 1,
        max = 255,
        message = "Title must be between 1 to 255 characters long."
    ))]
    #[schema(example = "My First Note", required = true)]
    pub title: String,
    #[schema(example = "This is my first body note.")]
    pub body: String,
}

#[derive(Deserialize, Validate, ToSchema, Serialize)]
pub struct NoteUpdatePayload {
    #[validate(length(
        min = 1,
        max = 255,
        message = "Title must be between 1 to 255 characters long."
    ))]
    #[schema(example = "My First Note", required = true)]
    pub title: Option<String>,
    #[schema(example = "This is my first body note.")]
    pub body: Option<String>,
}
