use serde::{de, Deserialize, Deserializer};
use std::i64::MAX as I64Max;
use utoipa::IntoParams;

fn default_limit() -> i64 {
    I64Max
}
fn deserialize_limit<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    match value {
        Some(val) if val.is_empty() => Ok(I64Max),
        Some(val) => {
            if let Ok(parsed_val) = val.parse::<i64>() {
                if parsed_val > 0 {
                    return Ok(parsed_val);
                }
            }
            let err_msg = format!("Exepected a valid limit value between 1 and the maximum `i64` value ({}), but received '{}'.", I64Max, val);
            Err(de::Error::custom(err_msg))
        }
        None => Ok(I64Max),
    }
}
fn default_offset() -> i64 {
    0
}
fn deserialize_offset<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.is_empty() {
        return Ok(0);
    } else if let Ok(parsed_val) = value.parse::<i64>() {
        if parsed_val >= 0 {
            return Ok(parsed_val);
        }
    }
    let err_msg = format!("Exepected a valid offset value between 0 and the maximum `i64` value ({}), but received '{}'.", I64Max, value);
    Err(de::Error::custom(err_msg))
}
fn default_sort() -> String {
    String::from("DESC")
}
fn validate_sort<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let sort_str = String::deserialize(deserializer)?;
    if sort_str.eq_ignore_ascii_case("asc") || sort_str.eq_ignore_ascii_case("desc") {
        Ok(sort_str)
    } else {
        let err_msg = format!(
            "Invalid value for sort: '{}'. Expected 'ASC' or 'DESC'.",
            sort_str
        );
        // Err(de::Error::invalid_value(de::Unexpected::Str(&sort_str), &"ASC or DESC"))
        Err(de::Error::custom(err_msg))
    }
}
#[derive(Deserialize, IntoParams)]
pub struct GetAllNotesQueryParams {
    #[serde(default = "default_limit", deserialize_with = "deserialize_limit")]
    pub limit: i64,
    #[serde(default = "default_offset", deserialize_with = "deserialize_offset")]
    pub offset: i64,
    pub search: Option<String>,
    #[serde(default = "default_sort", deserialize_with = "validate_sort")]
    pub sort: String,
}

#[derive(Deserialize, IntoParams)]
pub struct GetNotePathParams {
    pub id: i32,
}

#[derive(Deserialize, IntoParams)]
pub struct UpdateNotePathParams {
    pub id: i32,
}

#[derive(Deserialize, IntoParams)]
pub struct DeleteNotePathParams {
    pub id: i32,
}
