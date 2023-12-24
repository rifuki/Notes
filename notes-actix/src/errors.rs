use actix_web::{HttpResponse, ResponseError};
use serde::Serialize;
use serde_json::{json, Map as JsonMap, Value as JsonValue};
use sqlx::Error as SqlxError;
use thiserror::Error as ThisError;
use validator::ValidationErrors;

#[derive(ThisError, Debug)]
pub enum AppError {
    #[error("Internal Server Error: {0}")]
    InternalServerError(JsonValue),
    #[error("Not Found: {0}")]
    NotFound(JsonValue),
    #[error("Unprocessable Entity: {0}")]
    UnprocessableEntity(JsonValue),
}
impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        match self {
            Self::InternalServerError(ref error) => HttpResponse::InternalServerError().json(error),
            Self::NotFound(ref error) => HttpResponse::NotFound().json(error),
            Self::UnprocessableEntity(ref error) => HttpResponse::UnprocessableEntity().json(error),
        }
    }
}

// Builder for AppError
pub struct AppErrorBuilder<T> {
    code: u16,
    message: String,
    details: Option<T>,
}
impl<T> AppErrorBuilder<T>
where
    T: Serialize,
{
    pub fn new(code: u16, message: String, details: Option<T>) -> Self {
        Self {
            code,
            message,
            details,
        }
    }

    pub fn internal_server_error(self) -> AppError {
        AppError::InternalServerError(self.into())
    }
    pub fn not_found(self) -> AppError {
        AppError::NotFound(self.into())
    }
    pub fn unprocessable_entity(self) -> AppError {
        AppError::UnprocessableEntity(self.into())
    }
}
impl<T> From<AppErrorBuilder<T>> for JsonValue
where
    T: Serialize,
{
    fn from(error: AppErrorBuilder<T>) -> Self {
        match error.details {
            Some(details) => json!({
                "code": error.code,
                "message": error.message,
                "details": details
            }),
            None => json!({
                "code": error.code,
                "message": error.message
            }),
        }
    }
}

// Validation errors
impl From<ValidationErrors> for AppError {
    fn from(validation_errors: ValidationErrors) -> Self {
        let mut cleaned_errors = JsonMap::new();

        for (field, errors) in validation_errors.field_errors().iter() {
            let errors = errors
                .iter()
                .map(|error| error.message.clone().unwrap().to_string())
                // .map(|error| json!(error.message))
                .collect::<Vec<String>>();
            // .collect::<Vec<JsonValue>>();
            cleaned_errors.insert(field.to_string(), json!(errors));
        }

        AppErrorBuilder::<JsonMap<String, JsonValue>>::new(
            422,
            String::from("Validation Error"),
            Some(cleaned_errors),
        )
        .unprocessable_entity()
    }
}

// Database error
impl From<SqlxError> for AppError {
    fn from(error: SqlxError) -> Self {
        AppErrorBuilder::new(
            500,
            String::from("An database error occured while processing your request."),
            Some(error.to_string()),
        )
        .internal_server_error()
    }
}
