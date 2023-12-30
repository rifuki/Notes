use actix_web::{http::StatusCode, web, HttpResponse};
use serde_json::json;
use sqlx::query_as as SqlxQueryAs;
use std::i64::MAX as I64Max;
use validator::Validate;

use crate::{
    errors::{AppError, AppErrorBuilder},
    helpers::is_access_token_blacklisted,
    jwt::JwtAuth,
    notes::{
        models::{Note, NoteBuilder, NoteJoinUser, NoteUpdatePayload},
        types::{
            DeleteNotePathParams, GetAllNotesQueryParams, GetNotePathParams, UpdateNotePathParams,
        },
    },
    types::{AppState, UserRole},
};

/// This endpoint handles the retrieval of notes.
///
/// ## Query Parameters
/// - `search`: A parameter to filter notes based on title or body content.
/// - `limit`: Limit the number of notes to retrieve. Defaults to all if not specified.
/// - `offset`: Pagination offset for the retrieved notes.
/// - `sort`: Specifies the sorting order for the retrieved notes. Can be ascending or descending.
///
/// ## Responses
/// - 200 OK: Successfully retrieved notes.
///   - Returns a list of notes matching the provided search criteria along with pagination details.
///   - Possible examples include lists of notes retrieved based on different search criteria or limits.
///
/// - 404 Not Found: Notes not found based on the search criteria.
///   - Returns an empty list of notes with a message indicating no notes found for the given search criteria.
///
/// - 500 Internal Server Error: Unexpected error occurred while processing the request.
///
/// The examples include responses for different scenarios such as successfully retrieving notes based on search criteria,
/// pagination, and when no notes are found matching the provided search criteria.
#[utoipa::path(
    get,
    tag = "Notes Endpoint",
    path = "/api/v1/notes",
    params(GetAllNotesQueryParams),
    responses(
        (status = 200, description = "Succesfully retrieved all notes.", body = NoteJoinUser, content_type = "application/json", examples(
            ("List of Notes" = (
                value = json!({
                    "code": 200,
                    "length": 3,
                    "message": "Succesfully retrieved all notes.",
                    "notes": [
                        {
                            "code": 200,
                            "length": 3,
                            "message": "Successfully retrieved all notes.",
                            "notes": [
                                {
                                    "body": "This is my third body note.",
                                    "createdAt": "2023-12-27T16:54:41.325218",
                                    "id": 3,
                                    "title": "My Third Note",
                                    "updatedAt": "2023-12-27T16:54:41.325218",
                                    "user_id": 1,
                                    "username": "john"
                                },
                                {
                                    "body": "This is my second body note.",
                                    "createdAt": "2023-12-27T16:54:39.222193",
                                    "id": 2,
                                    "title": "My Second Note",
                                    "updatedAt": "2023-12-27T16:54:39.222193",
                                    "user_id": 1,
                                    "username": "john"
                                },
                                {
                                    "body": "This is my first body note.",
                                    "createdAt": "2023-12-27T16:49:13.729911",
                                    "id": 1,
                                    "title": "My First Note",
                                    "updatedAt": "2023-12-27T16:49:13.729911",
                                    "user_id": 1,
                                    "username": "john"
                                }
                            ]
                        }
                    ]
                })
            )),
            ("List of Notes based on search criteria" = (
                value = json!({
                    "code": 200,
                    "length": 1,
                    "message": "Successfully retrieved all notes based on search criteria: 'My Title'",
                    "notes": [
                        {
                            "body": "This is my first body note.",
                            "createdAt": "2023-12-27T16:49:13.729911",
                            "id": 1,
                            "title": "My First Note",
                            "updatedAt": "2023-12-27T16:49:13.729911",
                            "user_id": 1,
                            "username": "john"
                        }
                    ]
                })
            )),
            ("List of Notes with a limit" = (
                value = json!({
                    "code": 200,
                    "length": 1,
                    "message": "Successfully retrieved all notes with limit: 1",
                    "notes": [
                        {
                            "body": "This is my third body note.",
                            "createdAt": "2023-12-27T16:54:41.325218",
                            "id": 3,
                            "title": "My Third Note",
                            "updatedAt": "2023-12-27T16:54:41.325218",
                            "user_id": 1,
                            "username": "john"
                        }
                    ]
                })
            )),
            ("List of Notes with a limit and based on search criteria: 'note' " = (
                value = json!({
                    "code": 200,
                    "length": 1,
                    "message": "Successfully retrieved all notes with limit: 1 and based on search criteria: 'first'",
                    "notes": [
                        {
                            "body": "This is my third body note.",
                            "createdAt": "2023-12-27T16:54:41.325218",
                            "id": 3,
                            "title": "My Third Note",
                            "updatedAt": "2023-12-27T16:54:41.325218",
                            "user_id": 1,
                            "username": "john"
                        },
                    ]
                })
            )),
            ("Notes Empty" = (
                value = json!({
                    "code": 200,
                    "length": 0,
                    "message": "Notes is empty",
                    "notes": []
                })
            )),
        )),
        (status = 401, description = "Unauthorized - Access denied due to failed authentication validation or invalid credentials.", body = isize, content_type = "application/json", examples (
            ("Not yet authorized" = (
                value = json!({
                    "code": 403,
                    "message": "You're not authorized to access this endpoint."
                })
            )),
            ("Token expired" = (
                value = json!({
                    "code": 401,
                    "message": "Your Access token has expired. Please refresh your access token or log in again. 2"
                })
            )),
            ("Invalid token" = (
                value = json!({
                    "code": 401,
                    "details": "Invalid token",
                    "message": "Your acess token is broken. Please log in again."
                })
            ))
        )),
        (status = 404, description = "Notes not found based the search criteria.", body = String, content_type = "application/json",
            example = json!({
                "code": 404,
                "length": 0,
                "message": "No Notes found matching the search criteria.",
                "notes": []
            })
        ),
        (status = 500, description = "Unexpected error occurred while processing the request.")
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn get_all_notes(
    jwt_auth: JwtAuth,
    app_state: web::Data<AppState>,
    qp: web::Query<GetAllNotesQueryParams>,
) -> Result<HttpResponse, AppError> {
    let redis_pool = app_state.get_ref().redis_pool.get().await.unwrap();

    let auth_id = jwt_auth.aud;
    let auth_role = jwt_auth.sub.role;

    let is_token_blacklisted = is_access_token_blacklisted(auth_id, redis_pool).await;
    if let Err(err) = is_token_blacklisted {
        return Err(err);
    }

    let compose_sql_query;
    let sql_query = if auth_role == UserRole::Admin.to_string() {
        compose_sql_query = format!(
            "SELECT notes.*, users.username FROM notes
            LEFT JOIN users ON notes.user_id = users.id 
            WHERE 1=1 {} ORDER BY updated_at {} LIMIT $1 OFFSET $2",
            if let Some(query_search) = &qp.search {
                format!(
                    " AND (notes.title ILIKE '%{}%' OR notes.body ILIKE '%{}%')",
                    query_search, query_search
                )
            } else {
                String::new()
            },
            qp.sort,
        );
        SqlxQueryAs::<_, NoteJoinUser>(&compose_sql_query)
            .bind(qp.limit)
            .bind(qp.offset)
    } else {
        compose_sql_query = format!(
            "SELECT notes.*, users.username FROM notes
             LEFT JOIN users ON notes.user_id = users.id 
             WHERE user_id = $1 {} ORDER BY updated_at {} LIMIT $2 OFFSET $3",
            if let Some(query_search) = &qp.search {
                format!(
                    " AND (notes.title ILIKE '%{}%' OR notes.body ILIKE '%{}%')",
                    query_search, query_search
                )
            } else {
                String::new()
            },
            qp.sort
        );
        SqlxQueryAs::<_, NoteJoinUser>(&compose_sql_query)
            .bind(auth_id)
            .bind(qp.limit)
            .bind(qp.offset)
    };

    let db_pool = &app_state.get_ref().db_pool;
    let stored_notes = sql_query.fetch_all(db_pool).await.map_err(|err| {
        log::error!("[get_all_notes] Failed to retrieve all notes: {:?}", err);
        AppErrorBuilder::<bool>::new(
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            String::from("Could not retrieve notes."),
            None,
        )
        .internal_server_error()
    })?;

    // Constructs the response body to be sent back after a successful get all notes. 🔥
    let mut status_code = StatusCode::OK;
    let response_message = if let Some(search_criteria) = &qp.search {
        if stored_notes.is_empty() {
            status_code = StatusCode::NOT_FOUND;
            format!(
                "No notes found matching the search criteria: '{}'",
                search_criteria
            )
        } else if qp.limit == I64Max {
            format!(
                "Successfully retrieved all notes based on search criteria: '{}'",
                search_criteria
            )
        } else {
            format!(
                "Successfully retrieved all notes with limit: {} based on search criteria: '{}'.",
                qp.limit, search_criteria
            )
        }
    } else {
        if stored_notes.is_empty() {
            String::from("Notes is empty.")
        } else if qp.limit == I64Max {
            String::from("Successfully retrieved all notes.")
        } else {
            format!("Successfully retrieved all notes with limit: {}", qp.limit)
        }
    };

    let response_body = json!({
        "code": status_code.as_u16(),
        "message": response_message,
        "length": stored_notes.len(),
        "notes": stored_notes
    });
    Ok(HttpResponse::build(status_code).json(response_body))
}

/// Handle the creation of a new note.
/// This endpoint allows users to create a new note with provided title and body.
///
/// Successful creation will return the newly created note.
/// - Status Code 201: Succesfully created a new note.
///
/// Possible error responses:
/// - Status Code 400: Invalid request input.
/// - Status Code 422: Request input validation failed, rendering the request unprocessable.
/// - Status Code 500: Unexpected server-side error during request processing.
#[utoipa::path(
    post,
    tag = "Notes Endpoint", 
    path = "/api/v1/notes",
    request_body(content = NoteBuilder, description = "JSON payload containing the title and body of the note.", content_type = "application/json"),
    responses(
        (status = 201, description = "Successfully created new note.", content_type = "application/json", body = Note,
            example = json!({
                "code": 201,
                "message": "Note created successfully.",
                "note": {
                    "body": "This is my first body note.",
                    "createdAt": "2023-12-27T16:49:13.729911",
                    "id": 1,
                    "title": "My First Note",
                    "updatedAt": "2023-12-27T16:49:13.729911",
                    "user_id": 1
                }
            }),
        ),
        (status = 400, description = "Invalid request input.", body = String, content_type = "text/plain",
            example = json!("Json deserialize error: missing field `title` at line 4 column 1")
        ),
        (status = 401, description = "Unauthorized - Access denied due to failed authentication validation or invalid credentials.", body = isize, content_type = "application/json", examples (
            ("Not yet authorized" = (
                value = json!({
                    "code": 403,
                    "message": "You're not authorized to access this endpoint."
                })
            )),
            ("Token expired" = (
                value = json!({
                    "code": 401,
                    "message": "Your Access token has expired. Please refresh your access token or log in again. 2"
                })
            )),
            ("Invalid token" = (
                value = json!({
                    "code": 401,
                    "details": "Invalid token",
                    "message": "Your acess token is broken. Please log in again."
                })
            ))
        )),
        (status = 422, description = "Request input validation failed, rendering the request unprocessable.", body = String, 
            example = json!({
                "code": 422,
                "details": {
                    "title": [
                        "Title must be between 1 to 255 characters long."
                    ]
                },
                "message": "Validation Error"
            })
        ),
        (status = 500, description = "Unexpected server-side error during request processing.")
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn create_note(
    jwt_auth: JwtAuth,
    app_state: web::Data<AppState>,
    json_request: web::Json<NoteBuilder>,
) -> Result<HttpResponse, AppError> {
    let redis_pool = app_state.get_ref().redis_pool.get().await.unwrap();

    let auth_id = jwt_auth.aud;

    let is_token_blacklisted = is_access_token_blacklisted(auth_id, redis_pool).await;
    if let Err(err) = is_token_blacklisted {
        return Err(err);
    }

    let payload = json_request.into_inner();
    if let Err(payload) = payload.validate() {
        return Err(payload.into());
    }

    let db_pool = &app_state.get_ref().db_pool;
    let inserted_note = SqlxQueryAs::<_, Note>(
        "INSERT INTO notes (title, body, user_id) VALUES ($1, $2, $3) RETURNING *",
    )
    .bind(payload.title)
    .bind(payload.body)
    .bind(auth_id)
    .fetch_optional(db_pool)
    .await
    .map_err(|err| {
        log::error!("[create_note] Failed to create new note. {}", err);
        AppErrorBuilder::new(
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            format!("Could not create note: {}", err),
            Some(err.to_string()),
        )
        .internal_server_error()
    })?
    .ok_or_else(|| {
        AppErrorBuilder::<bool>::new(
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            "Could not create note".to_string(),
            None,
        )
        .internal_server_error()
    })?;

    // Constructs the response body to be sent back after a successful stored note. 🔥
    let status_code = StatusCode::CREATED;
    let response_body = json!({
        "code": status_code.as_u16(),
        "message": "Note created successfully.",
        "note": inserted_note
    });
    Ok(HttpResponse::build(status_code).json(response_body))
}

/// Retrieves a specific note identified by the provided `id` path parameter.
/// This endpoint retrieves a note with the specified ID.
///
/// # Arguments
/// * `app_state`: The shared application state containing the database connection pool.
/// * `pp`: The path parameter containing the `id` of the note to be retrieved.
///
/// # Returns
///
/// A `Result` containing an `HttpResponse` on success, or an `AppError` on failure.
///
/// ## Response
/// - 200 OK: Successfully retrieved the specified note.
/// -   - Returns a JSON with the retrieved note data.
/// - 404 Not Found: Requested note does not exist.
/// -   - Returns a JSON object indicating that the note with the specified `id` was not found.
/// - 500 Internal Server Error: Internal Server Error occured.
/// -    - Returns a JSON object indicating a failure to retrieve the note due to an unexpected server error.
#[utoipa::path(
    get,
    tag = "Notes Endpoint",
    path = "/api/v1/notes/{id}",
    params(GetNotePathParams),
    responses(
        // Status 200 response details
        (status = 200, description = "Successfully retrieved the specified note.", body = Note, content_type = "application/json", 
            example = json!({
                "code": 200,
                "message": "Note retrieved successfully."
            })
        ),
        (status = 401, description = "Unauthorized - Access denied due to failed authentication validation or invalid credentials.", body = isize, content_type = "application/json", examples (
            ("Not yet authorized" = (
                value = json!({
                    "code": 403,
                    "message": "You're not authorized to access this endpoint."
                })
            )),
            ("Token expired" = (
                value = json!({
                    "code": 401,
                    "message": "Your Access token has expired. Please refresh your access token or log in again. 2"
                })
            )),
            ("Invalid token" = (
                value = json!({
                    "code": 401,
                    "details": "Invalid token",
                    "message": "Your acess token is broken. Please log in again."
                })
            ))
        )),
        // Status 404 response details
        (status = 404, description = "Requested note does not exist.", body = String,
            example = json!({
                "code": 404,
                "message": "Note not found."
            })
        ),
        // Status 500 response details
        (status = 500, description = "Internal Server Error occurred.", body = String,
            example = json!({
                "code": 500,
                "message": "Failed retrieve note with id: '1'.",
                "details": "An unexpected error occurred during the retrieval process."
            })
        )
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn get_note(
    jwt_auth: JwtAuth,
    app_state: web::Data<AppState>,
    pp: web::Path<GetNotePathParams>,
) -> Result<HttpResponse, AppError> {
    let redis_pool = app_state.get_ref().redis_pool.get().await.unwrap();

    let note_id = pp.into_inner().id;
    let auth_id = jwt_auth.aud;
    let auth_role = jwt_auth.sub.role;

    let is_token_blacklisted = is_access_token_blacklisted(auth_id, redis_pool).await;
    if let Err(err) = is_token_blacklisted {
        return Err(err);
    }

    let sqlx_query = if auth_role == UserRole::Admin.to_string() {
        SqlxQueryAs::<_, NoteJoinUser>("SELECT notes.*, users.username FROM notes LEFT JOIN users ON notes.user_id = users.id WHERE notes.id = $1;").bind(note_id)
    } else {
        SqlxQueryAs::<_, NoteJoinUser>("SELECT notes.*, users.username FROM notes LEFT JOIN users ON notes.user_id = users.id WHERE notes.id = $1 AND user_id = $2;")
            .bind(note_id)
            .bind(auth_id)
    };

    let db_pool = &app_state.get_ref().db_pool;
    let stored_note = sqlx_query
        .fetch_optional(db_pool)
        .await
        .map_err(|err| {
            log::error!(
                "[get_user] Failed to retrieve note with id: '{}'. {}",
                note_id,
                err
            );
            AppErrorBuilder::new(
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                format!("Failed retrieve note with id: '{}'", note_id),
                Some(err.to_string()),
            )
            .internal_server_error()
        })?
        .ok_or_else(|| {
            AppErrorBuilder::<bool>::new(
                StatusCode::NOT_FOUND.as_u16(),
                String::from("Note not found."),
                None,
            )
            .not_found()
        })?;

    // Constructs the response body to be sent back after a successful get note. 🔥
    let status_code = StatusCode::OK;
    let response_body = json!({
        "code": status_code.as_u16(),
        "message": "Note retrieved successfully.",
        "note": stored_note
    });
    Ok(HttpResponse::build(status_code).json(response_body))
}

/// Update a specific note identified by the provided `id` path parameter.
///
/// This endpoint updates the title and body of the note with the specified ID.
///
/// # Arguments
///
/// * `app_state`:  The shared application state containing the database connection pool.
/// * `pp`: The path parameter containing the `id` of the note to be updated.
/// * `json_request`: The JSON payload containing the updated title and body for the note.
///
/// # Returns
///
/// A `Result` containing an `HttpResponse` on success, or an `AppError` on failure.
///
/// ## Request Body
///
/// The request body must contain a JSON object with the following fields:
/// - `title`: The updated title for the note.
/// - `body`: The updated body content for the note.
///
/// ## Response
/// - 200 OK: Successfully updated the specified note.
/// -   - Returns a JSON object with the updated note data.
/// - 400 Bad Request: Invalid request input.
/// -   - Returns a plaintext message indicating a JSON deserialization error due to missing `title` or `body` fields in the provided JSON.
/// - 422 Unprocessable Entity: Validation error occured.
/// -   - Returns a JSON object indicating the validation errors encountered during the update process.
/// - 404 Not Found: Requested note does not exist.
/// -   - Returns a JSON object indicating that the note with the specified `id` was not found.
/// - 500 Internal Server Error: Internal Server Error occured.
/// -   - Returns a JSON object indicating a failure to update the note due to an unexpected server error.
#[utoipa::path(
    put,
    tag = "Notes Endpoint",
    path = "/api/v1/notes/{id}",
    params(UpdateNotePathParams),
    request_body(content = NoteBuilder, description = "JSON payload containing the title and body of the note.", content_type = "application/json"),
    responses(
        (status = 200, description = "Successfully updated the specified note.", body = Note, content_type = "application/json",
            example = json!({
                "code": 200,
                "message": "Note updated successfully.",
            })
        ),
        (status = 400, description = "Invalid request input", body = String, content_type = "text/plain",
            example = json!("Json deserialize error: missing field `title` at line 4 column 1")
        ),
        (status = 401, description = "Unauthorized - Access denied due to failed authentication validation or invalid credentials.", body = isize, content_type = "application/json", examples (
            ("Not yet authorized" = (
                value = json!({
                    "code": 403,
                    "message": "You're not authorized to access this endpoint."
                })
            )),
            ("Token expired" = (
                value = json!({
                    "code": 401,
                    "message": "Your Access token has expired. Please refresh your access token or log in again. 2"
                })
            )),
            ("Invalid token" = (
                value = json!({
                    "code": 401,
                    "details": "Invalid token",
                    "message": "Your acess token is broken. Please log in again."
                })
            ))
        )),
        (status = 404, description = "Requested note does not exist.", body = String,
            example = json!({
                "code": 404,
                "message": "Note not found."
            })
        ),
        (status = 422, description = "Request input validation failed, rendering the request unprocessable", body = String, 
            example = json!({
                "code": 422,
                "details": {
                    "title": [
                        "Title must be between 1 to 255 characters long."
                    ]
                },
                "message": "Validation Error"
            })
        ),
        (status = 500, description = "Unexpected server-side error during request processing.", body = String,
            example = json!({
                "code": 500,
                "message": "Failed update note with id: '144'.",
                "details": "An unexpected error occurred during the update process."
            })
        )
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn update_note(
    jwt_auth: JwtAuth,
    app_state: web::Data<AppState>,
    pp: web::Path<UpdateNotePathParams>,
    json_request: web::Json<NoteUpdatePayload>,
) -> Result<HttpResponse, AppError> {
    let redis_pool = app_state.get_ref().redis_pool.get().await.unwrap();

    let note_id = pp.into_inner().id;
    let auth_id = jwt_auth.aud;
    let auth_role = jwt_auth.sub.role;

    let is_token_blacklisted = is_access_token_blacklisted(auth_id, redis_pool).await;
    if let Err(err) = is_token_blacklisted {
        return Err(err);
    }

    let payload = json_request.into_inner();
    if let Err(payload) = payload.validate() {
        return Err(payload.into());
    }

    let db_pool = &app_state.get_ref().db_pool;
    let sql_query_get_stored_note = if &auth_role == &UserRole::Admin.to_string() {
        sqlx::query_as::<_, Note>("SELECT * FROM notes WHERE id = $1;").bind(note_id)
    } else {
        sqlx::query_as::<_, Note>("SELECT * FROM notes WHERE id = $1 AND user_id = $2;")
            .bind(note_id)
            .bind(auth_id)
    };
    let stored_note = sql_query_get_stored_note
        .fetch_optional(db_pool)
        .await
        .map_err(|err| {
            log::error!(
                "[update_note] Failed to retrieve note with id: '{}'. {}",
                note_id,
                err
            );
            AppErrorBuilder::new(
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                format!("Failed retrieve note with id: '{}'", note_id),
                Some(err.to_string()),
            )
            .internal_server_error()
        })?
        .ok_or_else(|| {
            AppErrorBuilder::<bool>::new(
                StatusCode::NOT_FOUND.as_u16(),
                String::from("Note not found. 1"),
                None,
            )
            .not_found()
        })?;

    let title = payload.title.unwrap_or(stored_note.title);
    let body = payload.body.unwrap_or(stored_note.body);

    let sql_query_update_note = if auth_role == UserRole::Admin.to_string() {
        SqlxQueryAs::<_, Note>("UPDATE notes SET title = $1, body = $2 WHERE id = $3 RETURNING *;")
            .bind(&title)
            .bind(&body)
            .bind(note_id)
    } else {
        SqlxQueryAs::<_, Note>(
            "UPDATE notes SET title = $1, body = $2 WHERE id = $3 AND user_id = $4 RETURNING *;",
        )
        .bind(&title)
        .bind(&body)
        .bind(note_id)
        .bind(auth_id)
    };
    let updated_note = sql_query_update_note
        .fetch_optional(db_pool)
        .await
        .map_err(|err| {
            log::error!(
                "[update_note] Failed to update note with id: '{}'. {}",
                note_id,
                err
            );
            AppErrorBuilder::new(
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                format!("Failed to update note with id: '{}'", note_id),
                Some(err.to_string()),
            )
            .internal_server_error()
        })?
        .ok_or_else(|| {
            AppErrorBuilder::<bool>::new(
                StatusCode::NOT_FOUND.as_u16(),
                String::from("Note not found. 2"),
                None,
            )
            .not_found()
        })?;

    // Constructs the response body to be sent back after a successful note update. 🔥
    let status_code = StatusCode::OK;
    let response_body = json!({
        "code": status_code.as_u16(),
        "message": format!("Note with id: '{}' updated successfully.", note_id),
        "note": updated_note
    });
    Ok(HttpResponse::build(status_code).json(response_body))
}

/// This endpoint handles the deletion of a note by its ID.
///
/// ## Path Parameters
/// - `id`: The identifier of the note to be deleted.
///
/// ## Responses
/// - 200 OK: Successfully deleted the specified note.
///   - Returns the details of the deleted note along with a success message.
///
/// - 404 Not Found: Invalid request input or the requested note does not exist.
///   - Possible scenarios include the note not being found or an error in parsing the path parameters.
///   - Provides a message indicating the note with the specified ID was not found.
///
/// - 500 Internal Server Error: Unexpected error occurred during request processing.
///   - Indicates an unexpected error during the delete process with additional details.
///
/// Examples for response details are provided for 404 and 500 status codes, specifying different scenarios that might occur.
#[utoipa::path(
    delete,
    tag = "Notes Endpoint",
    path = "/api/v1/notes/{id}",
    params(DeleteNotePathParams),
    responses(
        (status = 200, description = "Successfully deleted the specified note.", body = Note, content_type = "application/json",
            example = json!({
                "code": 200,
                "message": "Note deleted successfully.",
            }),
        ),
        (status = 401, description = "Unauthorized - Access denied due to failed authentication validation or invalid credentials.", body = isize, content_type = "application/json", examples (
            ("Not yet authorized" = (
                value = json!({
                    "code": 403,
                    "message": "You're not authorized to access this endpoint."
                })
            )),
            ("Token expired" = (
                value = json!({
                    "code": 401,
                    "message": "Your Access token has expired. Please refresh your access token or log in again. 2"
                })
            )),
            ("Invalid token" = (
                value = json!({
                    "code": 401,
                    "details": "Invalid token",
                    "message": "Your acess token is broken. Please log in again."
                })
            ))
        )),
        (status = 404, description = "Invalid request input.", body = String, content_type = ["application/json", "text/plain"], examples(
            ("Not Found" = (
                description = "",
                value = json!({
                    "code": 404,
                    "message": "Note not found."
                })
            )),
            ("Failed parsing path parameters" = (
                description = "",
                value = json!("can not parse 'kotoba' to a i32")
            ))
        ) ),
        (status = 500, description = "Unexpected server-side error during request processing.", body = String, content_type = "application/json",
            example = json!({
                "code": 500,
                "message": "Failed delete note with id: '1'.",
                "details": "An unexpected error occurred during the delete process."
            })
        )
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn delete_note(
    jwt_auth: JwtAuth,
    app_state: web::Data<AppState>,
    pp: web::Path<DeleteNotePathParams>,
) -> Result<HttpResponse, AppError> {
    let redis_pool = app_state.get_ref().redis_pool.get().await.unwrap();

    let auth_id = jwt_auth.aud;
    let auth_role = jwt_auth.sub.role;
    let note_id = pp.into_inner().id;

    let is_token_blacklisted = is_access_token_blacklisted(auth_id, redis_pool).await;
    if let Err(err) = is_token_blacklisted {
        return Err(err);
    }

    let sql_query = if auth_role == UserRole::Admin.to_string() {
        SqlxQueryAs::<_, Note>("DELETE FROM notes WHERE id = $1 RETURNING *;").bind(note_id)
    } else {
        SqlxQueryAs::<_, Note>("DELETE FROM notes WHERE id = $1 AND user_id = $2 RETURNING *;")
            .bind(note_id)
            .bind(auth_id)
    };

    let db_pool = &app_state.get_ref().db_pool;
    let deleted_note = sql_query
        .fetch_optional(db_pool)
        .await
        .map_err(|err| {
            log::error!(
                "[delete_note] Failed to delete note with id: '{}'. {}",
                note_id,
                err
            );
            AppErrorBuilder::new(
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                format!("Failed to delete note with id: '{}'", note_id),
                Some(err.to_string()),
            )
            .internal_server_error()
        })?
        .ok_or_else(|| {
            AppErrorBuilder::<bool>::new(
                StatusCode::NOT_FOUND.as_u16(),
                String::from("Note not found."),
                None,
            )
            .not_found()
        })?;

    // Constructs the response body to be sent back after a successful note delete. 🔥
    let status_code = StatusCode::OK;
    let response_body = json!({
        "code": status_code.as_u16(),
        "message": "Note deleted successfully.",
        "note": deleted_note
    });
    Ok(HttpResponse::build(status_code).json(response_body))
}
