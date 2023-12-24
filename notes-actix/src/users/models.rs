use chrono::NaiveDateTime;
use serde::{de, Deserialize, Deserializer, Serialize};
use sqlx::{FromRow, Type as SqlxType};

#[derive(SqlxType, Serialize, Debug)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    User,
}
impl<'de> Deserialize<'de> for UserRole {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_lowercase().as_str() {
            "admin" => Ok(UserRole::Admin),
            "user" => Ok(UserRole::User),
            _ => Err(de::Error::invalid_value(
                de::Unexpected::Str(&s),
                &"admin or user",
            )),
        }
    }
}

#[derive(FromRow, Serialize, Debug)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password: String,
    pub email: Option<String>,
    pub role: UserRole,
    #[serde(rename = "createdAt")]
    pub created_at: NaiveDateTime,
    #[serde(rename = "updatedAt")]
    pub updated_at: NaiveDateTime,
}

#[derive(Deserialize, Debug)]
pub struct UserBuilder {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
}
