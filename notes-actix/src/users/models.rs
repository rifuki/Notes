use chrono::NaiveDateTime;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;
use validator::{Validate, ValidationError};

#[derive(FromRow, Serialize, Clone, ToSchema)]
pub struct User {
    #[schema(example = "1")]
    pub id: i32,
    #[schema(example = "john", required = true)]
    pub username: String,
    #[schema(
        example = "$argon2id$v=19$m=19456,t=2,p=1$/DbiJMPWhjO39B/SIcVksg$aKYrAF3tvl49QvZmbZNKgf6xPEwz+WIygRcl2Oc5rOY",
        required = true
    )]
    pub password: String,
    #[schema(example = "johndoe@gmail.com", required = false)]
    pub email: Option<String>,
    #[schema(example = "user")]
    pub role: String,
    #[schema(
        example = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6NCwidXNlcm5hbWUiOiJha2l6dWtpIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MDM1MTM0NzYsImV4cCI6MTcwMzUxMzQ3N30.JWmOV0Cs5M-qbaRRxnJe62ei9sMbROMCXoi-ZR1gsoE",
        required = false
    )]
    pub refresh_token: Option<String>,
    #[schema(example = "2023-12-25 14:13:32.302591")]
    #[serde(rename = "createdAt")]
    pub created_at: NaiveDateTime,
    #[schema(example = "2023-12-25 17:35:54.246533")]
    #[serde(rename = "updatedAt")]
    pub updated_at: NaiveDateTime,
}

#[derive(Serialize, FromRow, ToSchema)]
pub struct UserClaims {
    #[schema(example = "1")]
    pub id: i32,
    #[schema(example = "john")]
    pub username: String,
    #[schema(example = "user")]
    pub role: String,
}

#[derive(Deserialize, ToSchema, Validate)]
pub struct UserLoginPayload {
    #[schema(example = "john", required = true)]
    #[validate(
        regex(
            path = "RE_USERNAME",
            message = "Username must consist of alphanumeric characters and be at least 1 characters long."
        ),
        length(
            min = 1,
            max = 50,
            message = "Username length must be between 1 to 50 characters long."
        )
    )]
    #[serde(deserialize_with = "to_lowercase")]
    pub username: String,
    #[schema(example = "Johndoe123@", required = true)]
    #[validate(
        custom(
            function = "validate_password",
            message = "Password must contain at least one uppercase letter, one lowercase letter, one digit, one special characters, is at least 8 characters long, and does not contain spaces."
        ),
        length(
            min = 8,
            message = "Password length must be at least 8 characters long."
        ),
        regex(
            path = "RE_PASSWORD",
            message = "Password must be at least one special character."
        )
    )]
    pub password: String,
}

#[derive(Deserialize, ToSchema, Validate)]
pub struct UserRegisterPayload {
    #[schema(example = "john", required = true)]
    #[validate(
        regex(
            path = "RE_USERNAME",
            message = "Username must consist of alphanumeric characters and be at least 1 characters long."
        ),
        length(
            min = 1,
            max = 50,
            message = "Username length must be between 1 to 50 characters long."
        )
    )]
    #[serde(deserialize_with = "to_lowercase")]
    pub username: String,
    #[schema(example = "johndoe@gmail.com", required = false)]
    #[validate(
        custom = "validate_email",
        email(message = "Email must be a valid email address.")
    )]
    #[serde(deserialize_with = "to_option_lowercase")]
    pub email: Option<String>,
    #[schema(example = "Johndoe123@", required = true)]
    #[validate(
        custom(
            function = "validate_password",
            message = "Password must contain at least one uppercase letter, one lowercase letter, one digit, one special characters, is at least 8 characters long, and does not contain spaces."
        ),
        length(
            min = 8,
            message = "Password length must be at least 8 characters long."
        ),
        regex(
            path = "RE_PASSWORD",
            message = "Password must be at least one special character."
        )
    )]
    pub password: String,
    #[schema(example = "Johndoe123@", required = true)]
    #[validate(must_match(
        other = "password",
        message = "Password do not match. Please ensure both entries are identical."
    ))]
    #[serde(rename = "confirmPassword")]
    pub confirm_password: String,
}

#[derive(Deserialize, ToSchema)]
pub struct UserUpdatePayload {
    #[schema(example = "john", required = false)]
    pub username: Option<String>,
    #[schema(example = "Johndoe123@", required = false)]
    pub password: Option<String>,
    #[schema(example = "johndoe@gmail.com", required = false)]
    pub email: Option<String>,
}

lazy_static! {
    static ref RE_USERNAME: Regex = Regex::new(r"^[0-9a-zA-Z]{1,}$").unwrap();
    static ref RE_PASSWORD: Regex =
        Regex::new(r"^.*?[^.*?[!@#$%^&*?_+=~|.,:;(){}\[\]<>].*$].*$").unwrap();
}

fn to_lowercase<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(s.to_lowercase())
}

fn to_option_lowercase<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = Option::<String>::deserialize(deserializer)?;
    match s {
        Some(kotoba) => Ok(Some(kotoba.to_lowercase())),
        None => Ok(None),
    }
}

fn validate_password(password: &str) -> Result<(), ValidationError> {
    let special_chars = "!@#$%^&*?_-+=~|.,:;()[]{}<>";

    let mut has_whitespace = false;
    let mut has_lowercase = false;
    let mut has_uppercase = false;
    let mut has_digit = false;
    let mut has_special = false;

    for c in password.chars() {
        has_whitespace |= c.is_whitespace();
        has_lowercase |= c.is_lowercase();
        has_uppercase |= c.is_uppercase();
        has_digit |= c.is_digit(10);
        has_special |= special_chars.contains(c);
    }

    if !has_whitespace
        && has_lowercase
        && has_uppercase
        && has_digit
        && has_special
        && password.len() >= 8
    {
        Ok(())
    } else {
        Err(ValidationError::new("Invalid password."))
    }
}

fn validate_email(email: &str) -> Result<(), ValidationError> {
    let valid_domains = ["gmail", "outlook", "icloud", "yahoo", "mail", "aol"];

    let email_parts = email.split("@").collect::<Vec<&str>>();
    if email_parts.len() != 2 {
        // return Err(ValidationError {
        //     code: Cow::Borrowed("email_address"),
        //     message: Some(Cow::Borrowed("Invalid email format.")),
        //     params: vec![(Cow::Borrowed(""))], /* <- still error */
        // });
        return Err(ValidationError::new("Invalid email format."));
    }

    let domain_parts = email_parts[1].split(".").collect::<Vec<&str>>();
    if domain_parts.len() < 2 {
        return Err(ValidationError::new("Invalid domain format."));
    }

    let email_domain = domain_parts[0].to_lowercase();
    if !valid_domains.contains(&&*email_domain) {
        return Err(ValidationError::new(
            "Invalid email domain. Supported domains: gmail, outlook, icloud, yahoo, mail, aol",
        ));
    }

    Ok(())
}
